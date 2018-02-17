use std::os::unix::io::RawFd;

use nix::sys::epoll;

use errors::*;

pub fn watch(tun: RawFd) -> Result<()> {
    assert!(tun > 0);

    let epfd = epoll::epoll_create()?;

    epoll::epoll_ctl(
        epfd,
        epoll::EpollOp::EpollCtlAdd,
        tun,
        Some(&mut epoll::EpollEvent::new(
            epoll::EpollFlags::EPOLLIN,
            tun as u64,
        )),
    )?;

    loop {
        let mut events = [epoll::EpollEvent::empty(); 10];
        let valid = epoll::epoll_wait(epfd, &mut events, 1000)?;
        let valid = &events[..valid];

        for ev in valid {
            let mut buf = [0u8; 1024];
            let read = ::nix::unistd::read(ev.data() as RawFd, &mut buf)?;
            let buf = &buf[..read];
            println!(
                "event: {:?} {} {}",
                ev.events(),
                ev.data(),
                ::hex::encode(buf)
            );
        }
    }

    Ok(())
}
