//! Host GPU vendor (native-family selection). The engine renders canvas, WebGL and
//! WebGPU on the host GPU through ANGLE's Direct3D 11 backend, which uses DXGI adapter 0
//! (the adapter of the primary display). Its PCI vendor id tells the persona generator
//! and the launch gate which GPU maker the profile may claim.

/// PCI vendor id of DXGI adapter 0, or `None` when it cannot be read (no DXGI, no adapter,
/// a non-Windows developer host). Callers treat `None` as "unknown", never as a match.
/// The software adapter (Microsoft Basic Render Driver, 0x1414) is returned as is.
pub fn host_gpu_vendor_id() -> Option<u32> {
    imp::adapter0_vendor_id()
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    #[repr(C)]
    #[allow(dead_code)] // Read by DXGI only.
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    // IID_IDXGIFactory1 {770aae78-f26f-4dba-a829-253c83d1b387}
    const IID_IDXGI_FACTORY1: Guid = Guid {
        data1: 0x770a_ae78,
        data2: 0xf26f,
        data3: 0x4dba,
        data4: [0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87],
    };

    /// DXGI_ADAPTER_DESC (dxgi.h).
    #[repr(C)]
    #[allow(dead_code)] // Written by DXGI; only vendor_id is read.
    struct AdapterDesc {
        description: [u16; 128],
        vendor_id: u32,
        device_id: u32,
        sub_sys_id: u32,
        revision: u32,
        dedicated_video_memory: usize,
        dedicated_system_memory: usize,
        shared_system_memory: usize,
        adapter_luid_low: u32,
        adapter_luid_high: i32,
    }

    #[link(name = "dxgi")]
    extern "system" {
        fn CreateDXGIFactory1(riid: *const Guid, factory: *mut *mut c_void) -> i32;
    }

    // COM vtable slots: IUnknown 0..=2 (Release = 2); IDXGIObject 3..=6;
    // IDXGIFactory::EnumAdapters = 7; IDXGIAdapter::GetDesc = 8.
    type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;
    type EnumAdaptersFn = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type GetDescFn = unsafe extern "system" fn(*mut c_void, *mut AdapterDesc) -> i32;

    /// # Safety
    /// `obj` is a live COM interface pointer; `slot` is a method of its vtable.
    unsafe fn method(obj: *mut c_void, slot: usize) -> *const c_void {
        let vtbl = *(obj as *const *const *const c_void);
        *vtbl.add(slot)
    }

    pub fn adapter0_vendor_id() -> Option<u32> {
        // SAFETY: plain DXGI COM calls with the documented vtable layout; every interface
        // obtained is released exactly once, and nothing outlives this function.
        unsafe {
            let mut factory: *mut c_void = std::ptr::null_mut();
            if CreateDXGIFactory1(&IID_IDXGI_FACTORY1, &mut factory) < 0 || factory.is_null() {
                return None;
            }
            let release_factory: ReleaseFn =
                std::mem::transmute::<*const c_void, ReleaseFn>(method(factory, 2));
            let enum_adapters: EnumAdaptersFn =
                std::mem::transmute::<*const c_void, EnumAdaptersFn>(method(factory, 7));
            let mut adapter: *mut c_void = std::ptr::null_mut();
            let hr = enum_adapters(factory, 0, &mut adapter);
            let mut vendor = None;
            if hr >= 0 && !adapter.is_null() {
                let get_desc: GetDescFn =
                    std::mem::transmute::<*const c_void, GetDescFn>(method(adapter, 8));
                let mut desc: AdapterDesc = std::mem::zeroed();
                if get_desc(adapter, &mut desc) >= 0 {
                    vendor = Some(desc.vendor_id);
                }
                let release_adapter: ReleaseFn =
                    std::mem::transmute::<*const c_void, ReleaseFn>(method(adapter, 2));
                release_adapter(adapter);
            }
            release_factory(factory);
            vendor
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn adapter0_vendor_id() -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn detection_does_not_panic() {
        // Whatever the host (CI runners have no GPU or the software adapter), the call
        // returns without crashing.
        let _ = super::host_gpu_vendor_id();
    }
}
