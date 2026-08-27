#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app {
    use windows::{
        ApplicationModel::Core::{
            CoreApplication, CoreApplicationView, IFrameworkView, IFrameworkView_Impl,
            IFrameworkViewSource, IFrameworkViewSource_Impl,
        },
        UI::Core::CoreWindow,
        Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
        core::{Ref, Result, implement},
    };

    #[implement(IFrameworkViewSource)]
    struct ViewSource;

    impl IFrameworkViewSource_Impl for ViewSource_Impl {
        fn CreateView(&self) -> Result<IFrameworkView> {
            Ok(View.into())
        }
    }

    #[implement(IFrameworkView)]
    struct View;

    impl IFrameworkView_Impl for View_Impl {
        fn Initialize(&self, application_view: Ref<CoreApplicationView>) -> Result<()> {
            _ = application_view.ok()?;
            Ok(())
        }

        fn SetWindow(&self, window: Ref<CoreWindow>) -> Result<()> {
            window.ok()?.Activate()
        }

        fn Load(&self, _entry_point: &windows::core::HSTRING) -> Result<()> {
            Ok(())
        }

        fn Run(&self) -> Result<()> {
            Ok(())
        }

        fn Uninitialize(&self) -> Result<()> {
            Ok(())
        }
    }

    pub fn run() -> Result<()> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED)? };
        let source: IFrameworkViewSource = ViewSource.into();
        let result = CoreApplication::Run(&source);
        unsafe { RoUninitialize() };
        result
    }
}

#[cfg(windows)]
fn main() -> windows::core::Result<()> {
    app::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("vcore-windows-vpn-host is only available on Windows");
}
