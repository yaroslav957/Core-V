use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use kvm_bindings::kvm_userspace_memory_region;

fn main() {
    use std::io::Write;
    use std::ptr::null_mut;
    use std::slice;

    let mem_size = 0x4000;
    let guest_addr = 0x1000;

    #[cfg(target_arch = "x86_64")]
    let asm_code = &[
        0xba, 0xf8, 0x03, // `mov $0x3f8, %dx`
        0xb0, b'X',       // `mov $'X', %al`
        0xee,             // `out %al, %dx`
        0xf4              // `hlt`
    ];

    let kvm = Kvm::new().unwrap();
    let vm = kvm.create_vm().unwrap();

    let load_addr: *mut u8 = unsafe {
        libc::mmap(
            null_mut(),
            mem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
    };

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: guest_addr,
        memory_size: mem_size as u64,
        userspace_addr: load_addr as u64,
        flags: 0, /* на Русском: вырезал нахуй KVM_MEM_LOG_DIRTY_PAGES)))). На ежином: dshtpfk yf[eq] KVM_MEM_LOG_DIRTY_PAGES)))) */
    };

    unsafe { vm.set_user_memory_region(mem_region).unwrap() };

    unsafe {
        let mut slice = slice::from_raw_parts_mut(load_addr, mem_size);
        slice.write_all(asm_code).unwrap();
    }

    let mut vcpu_fd = vm.create_vcpu(0).unwrap();

    #[cfg(target_arch = "x86_64")]
    {
        let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

        let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
        vcpu_regs.rip = guest_addr as u64;
        vcpu_regs.rax = 0;
        vcpu_regs.rdx = 0;
        vcpu_regs.rflags = 0x2;
        vcpu_fd.set_regs(&vcpu_regs).unwrap();
    }

    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::Hlt => {
                println!("\nVM halted gracefully");
                break;
            },
            VcpuExit::IoOut(port, data) => {
                if port == 0x3f8 {
                    print!("{}", data[0] as char);
                }
            },
            VcpuExit::IoIn(port, data) => {
                data[0] = 0;
            },
            exit_reason => panic!("Unexpected exit: {:?}", exit_reason),
        }
    }
}