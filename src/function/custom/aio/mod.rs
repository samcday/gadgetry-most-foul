//! Linux native AIO driver for exact borrowed-buffer transfers.

use rustix::event::EventfdFlags;
use slab::Slab;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::{Error, ErrorKind, Result},
    mem::MaybeUninit,
    ops::Deref,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
    pin::Pin,
    ptr,
    sync::Arc,
    time::{Duration, Instant},
};

#[cfg(feature = "tokio")]
use std::fs::File;
#[cfg(feature = "tokio")]
use std::marker::{PhantomData, PhantomPinned};
#[cfg(feature = "tokio")]
use std::task::{Context as TaskContext, Poll};

mod sys;

pub use sys::opcode;

const REAP_BATCH: usize = 32;

/// eventfd provided by kernel.
#[derive(Debug, Clone)]
struct EventFd(Arc<OwnedFd>);

impl EventFd {
    /// Create new nonblocking eventfd with initial value and semaphore characteristics, if requested.
    fn new(initval: u32, semaphore: bool) -> Result<Self> {
        let mut flags = EventfdFlags::NONBLOCK;
        if semaphore {
            flags |= EventfdFlags::SEMAPHORE;
        }
        let fd = rustix::event::eventfd(initval, flags)?;
        Ok(Self(Arc::new(fd)))
    }

    /// Decrease value by one or set to zero if using semaphore characteristics.
    fn read(&self) -> Result<u64> {
        let mut buf = [0; 8];
        let n = rustix::io::read(&*self.0, &mut buf).map_err(Error::from)?;
        if n != buf.len() {
            return Err(Error::other("short read from eventfd"));
        }

        Ok(u64::from_ne_bytes(buf))
    }

    /// Drain completion notifications already mirrored into the AIO completion queue.
    fn drain(&self) -> Result<()> {
        loop {
            match self.read() {
                Ok(_) => {}
                Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err),
            }
        }
    }
}

impl AsFd for EventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// AIO context wrapper.
#[derive(Debug)]
struct Context(sys::ContextId);

impl Context {
    /// Create an asynchronous I/O context.
    fn new(nr_events: u32) -> Result<Self> {
        let mut id = 0;
        unsafe { sys::setup(nr_events, &mut id) }?;
        Ok(Self(id))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let _ = unsafe { sys::destroy(self.0) };
    }
}

impl Deref for Context {
    type Target = sys::ContextId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// AIO operation handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OpHandle(usize);

/// Completed AIO operation.
#[derive(Debug)]
struct CompletedOp {
    id: usize,
    res: i64,
}

impl CompletedOp {
    fn result(&self) -> Result<usize> {
        if self.res >= 0 {
            Ok(usize::try_from(self.res).unwrap_or(usize::MAX))
        } else {
            let errno = i32::try_from(-self.res).unwrap_or(i32::MAX);
            Err(Error::from_raw_os_error(errno))
        }
    }
}

/// Submitted kernel AIO request.
struct InFlight {
    iocb: Pin<Box<sys::IoCb>>,
}

impl InFlight {
    fn iocb_ptr(&mut self) -> *mut sys::IoCb {
        Pin::into_inner(self.iocb.as_mut()) as *mut _
    }
}

/// AIO driver.
pub struct Driver {
    aio: Context,
    eventfd: EventFd,
    active: Slab<InFlight>,
    completed: HashMap<usize, CompletedOp>,
    queue_len: usize,
    #[cfg(feature = "tokio")]
    async_eventfd: Option<tokio::io::unix::AsyncFd<EventFd>>,
}

impl fmt::Debug for Driver {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Driver")
            .field("aio", &self.aio)
            .field("active", &self.active.len())
            .field("completed", &self.completed.len())
            .field("queue_len", &self.queue_len)
            .finish()
    }
}

impl Driver {
    /// Create new AIO driver.
    pub fn new(queue_len: u32) -> Result<Self> {
        if queue_len == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "AIO queue length must be greater than zero"));
        }

        let aio = Context::new(queue_len)?;
        let eventfd = EventFd::new(0, false)?;

        Ok(Self {
            aio,
            eventfd,
            active: Slab::with_capacity(queue_len as usize),
            completed: HashMap::new(),
            queue_len: queue_len as usize,
            #[cfg(feature = "tokio")]
            async_eventfd: None,
        })
    }

    fn available_slots(&self) -> usize {
        self.queue_len.saturating_sub(self.active.len())
    }

    /// Submit one borrowed-buffer AIO operation.
    ///
    /// # Safety
    /// The caller must keep `buf..buf+nbytes` alive and stable until the returned
    /// handle is completed, cancelled, or reaped by this driver.
    unsafe fn submit_raw(&mut self, opcode: u16, fd: RawFd, buf: *mut u8, nbytes: usize) -> Result<OpHandle> {
        if self.available_slots() == 0 {
            return Err(Error::new(ErrorKind::WouldBlock, "no AIO queue space available"));
        }

        let nbytes =
            nbytes.try_into().map_err(|_| Error::new(ErrorKind::InvalidInput, "AIO buffer too large"))?;
        let entry = self.active.vacant_entry();
        let id = entry.key();
        let iocb =
            sys::IoCb::new(opcode, fd, buf, nbytes).with_resfd(self.eventfd.as_raw_fd()).with_data(id as u64);
        let mut op = InFlight { iocb: Box::pin(iocb) };
        let iocb_ptr = op.iocb_ptr();
        entry.insert(op);

        let mut iocbs = [iocb_ptr];
        match unsafe { sys::submit(*self.aio, 1, iocbs.as_mut_ptr()) } {
            Ok(1) => Ok(OpHandle(id)),
            Ok(_) => {
                self.active.remove(id);
                Err(Error::new(ErrorKind::WouldBlock, "AIO request not accepted"))
            }
            Err(err) => {
                self.active.remove(id);
                Err(err)
            }
        }
    }

    fn complete_event(&mut self, event: sys::IoEvent) {
        let Ok(id) = usize::try_from(event.data) else { return };
        if self.active.contains(id) {
            self.active.remove(id);
            self.completed.insert(id, CompletedOp { id, res: event.res });
        }
    }

    fn reap_with_min(&mut self, min_nr: libc::c_long, timeout: *const libc::timespec) -> Result<usize> {
        let mut events = [MaybeUninit::<sys::IoEvent>::uninit(); REAP_BATCH];
        let n = unsafe {
            sys::getevents(*self.aio, min_nr, events.len() as _, events.as_mut_ptr() as *mut _, timeout)
        }?;

        let n = usize::try_from(n).unwrap_or(0);
        for event in events.into_iter().take(n) {
            self.complete_event(unsafe { event.assume_init() });
        }
        Ok(n)
    }

    #[cfg(feature = "tokio")]
    fn reap_nonblocking(&mut self) -> Result<usize> {
        let mut total = 0;
        loop {
            let n = self.reap_with_min(0, ptr::null())?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok(total)
    }

    fn reap_blocking(&mut self) -> Result<usize> {
        if self.active.is_empty() {
            return Ok(0);
        }
        let n = self.reap_with_min(1, ptr::null())?;
        self.eventfd.drain()?;
        Ok(n)
    }

    fn reap_timeout(&mut self, timeout: Duration) -> Result<usize> {
        if self.active.is_empty() {
            return Ok(0);
        }

        let tv_sec =
            timeout.as_secs().try_into().map_err(|_| Error::new(ErrorKind::InvalidInput, "timeout too large"))?;
        let tv_nsec = timeout.subsec_nanos().into();
        let timeout = libc::timespec { tv_sec, tv_nsec };
        let n = self.reap_with_min(1, &timeout)?;
        self.eventfd.drain()?;
        Ok(n)
    }

    fn cancel_and_reap(&mut self, ids: impl IntoIterator<Item = usize>) -> Result<()> {
        let mut remaining: HashSet<usize> = ids.into_iter().collect();
        if remaining.is_empty() {
            return Ok(());
        }

        remaining.retain(|id| self.completed.remove(id).is_none());

        let ids_to_cancel: Vec<_> = remaining.iter().copied().collect();
        for id in ids_to_cancel {
            let Some(op) = self.active.get_mut(id) else {
                remaining.remove(&id);
                continue;
            };

            let mut event = MaybeUninit::<sys::IoEvent>::uninit();
            if unsafe { sys::cancel(*self.aio, op.iocb_ptr(), event.as_mut_ptr()) }.is_ok() {
                self.active.remove(id);
                remaining.remove(&id);
            }
        }

        while !remaining.is_empty() {
            self.reap_blocking()?;
            remaining.retain(|id| self.completed.remove(id).is_none());
            remaining.retain(|id| self.active.contains(*id));
        }

        Ok(())
    }

    #[cfg(feature = "tokio")]
    fn poll_reap(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<()>> {
        match self.reap_nonblocking() {
            Ok(0) => {}
            Ok(_) => return Poll::Ready(Ok(())),
            Err(err) => return Poll::Ready(Err(err)),
        }

        if self.async_eventfd.is_none() {
            match tokio::io::unix::AsyncFd::with_interest(self.eventfd.clone(), tokio::io::Interest::READABLE) {
                Ok(async_eventfd) => self.async_eventfd = Some(async_eventfd),
                Err(err) => return Poll::Ready(Err(err)),
            }
        }

        let async_eventfd = self.async_eventfd.as_mut().expect("async eventfd initialized");
        match async_eventfd.poll_read_ready(cx) {
            Poll::Ready(Ok(mut guard)) => {
                let read_res = guard.try_io(|async_fd| async_fd.get_ref().read().map(|_| ()));
                drop(guard);

                match read_res {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Poll::Ready(Err(err)),
                    Err(_) => {}
                }

                Poll::Ready(self.reap_nonblocking().map(|_| ()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                // The eventfd is only a wakeup hint; the AIO completion queue is
                // authoritative. Check it again after registering the waker so a
                // completion racing with readiness registration cannot sleep
                // until an unrelated later eventfd notification.
                match self.reap_nonblocking() {
                    Ok(0) => Poll::Pending,
                    Ok(_) => Poll::Ready(Ok(())),
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
        }
    }

    /// Execute a blocking exact read into a borrowed buffer.
    pub fn read_exact(
        &mut self, fd: RawFd, buf: &mut [u8], chunk_size: usize, timeout: Option<Duration>,
    ) -> Result<()> {
        let mut state = ExactState::new(TransferKind::Read, fd, buf.as_mut_ptr(), buf.len(), chunk_size);
        state.run_blocking(self, timeout)
    }

    /// Execute a blocking exact write from a borrowed buffer.
    pub fn write_all(
        &mut self, fd: RawFd, buf: &[u8], chunk_size: usize, timeout: Option<Duration>,
    ) -> Result<()> {
        let mut state = ExactState::new(TransferKind::Write, fd, buf.as_ptr() as *mut u8, buf.len(), chunk_size);
        state.run_blocking(self, timeout)
    }

    /// Create an async exact read future.
    #[cfg(feature = "tokio")]
    pub fn read_exact_async<'a>(
        &'a mut self, file: Arc<File>, buf: &'a mut [u8], chunk_size: usize,
    ) -> ReadExact<'a> {
        let fd = file.as_raw_fd();
        ReadExact::new(
            self,
            file,
            ExactState::new(TransferKind::Read, fd, buf.as_mut_ptr(), buf.len(), chunk_size),
        )
    }

    /// Create an async exact write future.
    #[cfg(feature = "tokio")]
    pub fn write_all_async<'a>(&'a mut self, file: Arc<File>, buf: &'a [u8], chunk_size: usize) -> WriteAll<'a> {
        let fd = file.as_raw_fd();
        WriteAll::new(
            self,
            file,
            ExactState::new(TransferKind::Write, fd, buf.as_ptr() as *mut u8, buf.len(), chunk_size),
        )
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let ids: Vec<_> = self.active.iter().map(|(id, _)| id).collect();
        let _ = self.cancel_and_reap(ids);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferKind {
    Read,
    Write,
}

impl TransferKind {
    fn opcode(self) -> u16 {
        match self {
            Self::Read => opcode::PREAD,
            Self::Write => opcode::PWRITE,
        }
    }

    fn short_error(self, expected: usize, actual: usize) -> Error {
        match self {
            Self::Read => Error::new(
                ErrorKind::UnexpectedEof,
                format!("short AIO read: expected {expected} bytes, received {actual}"),
            ),
            Self::Write => Error::new(
                ErrorKind::WriteZero,
                format!("short AIO write: expected {expected} bytes, wrote {actual}"),
            ),
        }
    }
}

#[derive(Debug)]
struct PendingChunk {
    len: usize,
}

#[derive(Debug)]
struct ExactState {
    kind: TransferKind,
    fd: RawFd,
    ptr: *mut u8,
    total_len: usize,
    chunk_size: usize,
    submitted: usize,
    completed: usize,
    submitted_zero: bool,
    pending: HashMap<usize, PendingChunk>,
}

impl ExactState {
    fn new(kind: TransferKind, fd: RawFd, ptr: *mut u8, total_len: usize, chunk_size: usize) -> Self {
        Self {
            kind,
            fd,
            ptr,
            total_len,
            chunk_size: chunk_size.max(1),
            submitted: 0,
            completed: 0,
            submitted_zero: false,
            pending: HashMap::new(),
        }
    }

    fn is_done(&self) -> bool {
        if !self.pending.is_empty() {
            return false;
        }

        match self.kind {
            TransferKind::Read => self.completed == self.total_len,
            TransferKind::Write if self.total_len == 0 => self.submitted_zero,
            TransferKind::Write => self.completed == self.total_len,
        }
    }

    fn submit_available(&mut self, driver: &mut Driver) -> Result<()> {
        if self.kind == TransferKind::Write && self.total_len == 0 && !self.submitted_zero {
            if driver.available_slots() == 0 {
                return Ok(());
            }
            let handle = unsafe { driver.submit_raw(self.kind.opcode(), self.fd, self.ptr, 0)? };
            self.pending.insert(handle.0, PendingChunk { len: 0 });
            self.submitted_zero = true;
            return Ok(());
        }

        while self.submitted < self.total_len && driver.available_slots() > 0 {
            let remaining = self.total_len - self.submitted;
            let len = remaining.min(self.chunk_size);
            let ptr = unsafe { self.ptr.add(self.submitted) };
            let handle = unsafe { driver.submit_raw(self.kind.opcode(), self.fd, ptr, len)? };
            self.pending.insert(handle.0, PendingChunk { len });
            self.submitted += len;
        }

        Ok(())
    }

    fn consume_completed(&mut self, driver: &mut Driver) -> Result<()> {
        while let Some(id) = self.pending.keys().find(|id| driver.completed.contains_key(id)).copied() {
            let comp = driver.completed.remove(&id).expect("completed exact AIO chunk disappeared");
            debug_assert_eq!(comp.id, id);
            let chunk = self.pending.remove(&id).expect("completed unknown exact AIO chunk");
            let actual = comp.result()?;
            if actual != chunk.len {
                return Err(self.kind.short_error(chunk.len, actual));
            }
            self.completed += actual;
        }

        Ok(())
    }

    fn cancel_blocking(&mut self, driver: &mut Driver) -> Result<()> {
        let ids: Vec<_> = self.pending.keys().copied().collect();
        driver.cancel_and_reap(ids)?;
        self.pending.clear();
        Ok(())
    }

    fn run_blocking(&mut self, driver: &mut Driver, timeout: Option<Duration>) -> Result<()> {
        let deadline = timeout
            .map(|timeout| {
                Instant::now()
                    .checked_add(timeout)
                    .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "timeout too large"))
            })
            .transpose()?;

        let res = loop {
            if let Err(err) = self.consume_completed(driver) {
                break Err(err);
            }
            if self.is_done() {
                break Ok(());
            }

            if let Err(err) = self.submit_available(driver) {
                break Err(err);
            }
            if let Err(err) = self.consume_completed(driver) {
                break Err(err);
            }
            if self.is_done() {
                break Ok(());
            }

            let reaped = match deadline {
                Some(deadline) => {
                    let remaining = deadline.checked_duration_since(Instant::now()).unwrap_or_default();
                    if remaining.is_zero() {
                        break Err(Error::new(ErrorKind::TimedOut, "timeout waiting for exact AIO transfer"));
                    }
                    driver.reap_timeout(remaining)
                }
                None => driver.reap_blocking(),
            };

            match reaped {
                Ok(0) => break Err(Error::new(ErrorKind::TimedOut, "timeout waiting for exact AIO transfer")),
                Ok(_) => {}
                Err(err) => break Err(err),
            }
        };

        if res.is_err() {
            let _ = self.cancel_blocking(driver);
        }
        res
    }
}

#[cfg(feature = "tokio")]
fn poll_exact(
    driver: &mut Driver, state: &mut ExactState, done: &mut bool, cx: &mut TaskContext<'_>,
) -> Poll<Result<()>> {
    if *done {
        return Poll::Ready(Ok(()));
    }

    loop {
        if let Err(err) = state.consume_completed(driver) {
            let _ = state.cancel_blocking(driver);
            *done = true;
            return Poll::Ready(Err(err));
        }
        if state.is_done() {
            *done = true;
            return Poll::Ready(Ok(()));
        }

        if let Err(err) = state.submit_available(driver) {
            let _ = state.cancel_blocking(driver);
            *done = true;
            return Poll::Ready(Err(err));
        }
        if let Err(err) = state.consume_completed(driver) {
            let _ = state.cancel_blocking(driver);
            *done = true;
            return Poll::Ready(Err(err));
        }
        if state.is_done() {
            *done = true;
            return Poll::Ready(Ok(()));
        }

        match driver.poll_reap(cx) {
            Poll::Ready(Ok(())) => continue,
            Poll::Ready(Err(err)) => {
                let _ = state.cancel_blocking(driver);
                *done = true;
                return Poll::Ready(Err(err));
            }
            Poll::Pending => return Poll::Pending,
        }
    }
}

/// Async exact read future.
#[cfg(feature = "tokio")]
pub struct ReadExact<'a> {
    driver: &'a mut Driver,
    _file: Arc<File>,
    state: ExactState,
    done: bool,
    _borrow: PhantomData<&'a mut [u8]>,
    _pin: PhantomPinned,
}

#[cfg(feature = "tokio")]
impl<'a> ReadExact<'a> {
    fn new(driver: &'a mut Driver, file: Arc<File>, state: ExactState) -> Self {
        Self { driver, _file: file, state, done: false, _borrow: PhantomData, _pin: PhantomPinned }
    }
}

#[cfg(feature = "tokio")]
impl std::future::Future for ReadExact<'_> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        poll_exact(this.driver, &mut this.state, &mut this.done, cx)
    }
}

#[cfg(feature = "tokio")]
impl Drop for ReadExact<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.state.cancel_blocking(self.driver);
            self.done = true;
        }
    }
}

#[cfg(feature = "tokio")]
unsafe impl Send for ReadExact<'_> {}

/// Async exact write future.
#[cfg(feature = "tokio")]
pub struct WriteAll<'a> {
    driver: &'a mut Driver,
    _file: Arc<File>,
    state: ExactState,
    done: bool,
    _borrow: PhantomData<&'a [u8]>,
    _pin: PhantomPinned,
}

#[cfg(feature = "tokio")]
impl<'a> WriteAll<'a> {
    fn new(driver: &'a mut Driver, file: Arc<File>, state: ExactState) -> Self {
        Self { driver, _file: file, state, done: false, _borrow: PhantomData, _pin: PhantomPinned }
    }
}

#[cfg(feature = "tokio")]
impl std::future::Future for WriteAll<'_> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        poll_exact(this.driver, &mut this.state, &mut this.done, cx)
    }
}

#[cfg(feature = "tokio")]
impl Drop for WriteAll<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.state.cancel_blocking(self.driver);
            self.done = true;
        }
    }
}

#[cfg(feature = "tokio")]
unsafe impl Send for WriteAll<'_> {}
