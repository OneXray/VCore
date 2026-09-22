use crate::{Result, VCoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Stopped,
    Preparing,
    Prepared,
    Starting,
    Running,
    Stopping,
    Failed,
}

impl LifecycleState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Preparing => "preparing",
            Self::Prepared => "prepared",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug)]
pub struct Lifecycle {
    state: LifecycleState,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            state: LifecycleState::Stopped,
        }
    }
}

impl Lifecycle {
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    pub fn transition(&mut self, next: LifecycleState) -> Result<()> {
        let valid = matches!(
            (self.state, next),
            (LifecycleState::Stopped, LifecycleState::Preparing)
                | (
                    LifecycleState::Preparing,
                    LifecycleState::Prepared | LifecycleState::Failed,
                )
                | (
                    LifecycleState::Prepared,
                    LifecycleState::Starting | LifecycleState::Stopped,
                )
                | (
                    LifecycleState::Starting,
                    LifecycleState::Running | LifecycleState::Failed,
                )
                | (
                    LifecycleState::Running,
                    LifecycleState::Stopping | LifecycleState::Failed,
                )
                | (LifecycleState::Failed, LifecycleState::Stopping)
                | (
                    LifecycleState::Stopping | LifecycleState::Failed,
                    LifecycleState::Stopped,
                )
        );

        if !valid {
            return Err(VCoreError::InvalidLifecycleTransition {
                from: self.state.as_str(),
                to: next.as_str(),
            });
        }

        self.state = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_is_serialized() {
        let mut lifecycle = Lifecycle::default();
        for next in [
            LifecycleState::Preparing,
            LifecycleState::Prepared,
            LifecycleState::Starting,
            LifecycleState::Running,
            LifecycleState::Stopping,
            LifecycleState::Stopped,
        ] {
            lifecycle.transition(next).unwrap();
        }
    }

    #[test]
    fn duplicate_start_is_rejected() {
        let mut lifecycle = Lifecycle::default();
        lifecycle.transition(LifecycleState::Preparing).unwrap();
        let error = lifecycle.transition(LifecycleState::Preparing).unwrap_err();
        assert!(matches!(
            error,
            VCoreError::InvalidLifecycleTransition { .. }
        ));
    }

    #[test]
    fn running_component_failure_can_be_observed_then_stopped() {
        let mut lifecycle = Lifecycle::default();
        for next in [
            LifecycleState::Preparing,
            LifecycleState::Prepared,
            LifecycleState::Starting,
            LifecycleState::Running,
            LifecycleState::Failed,
            LifecycleState::Stopping,
            LifecycleState::Stopped,
        ] {
            lifecycle.transition(next).unwrap();
        }
    }

    #[test]
    fn failed_prepare_and_start_can_be_cleaned_back_to_stopped() {
        for before_failure in [LifecycleState::Preparing, LifecycleState::Starting] {
            let mut lifecycle = Lifecycle::default();
            lifecycle.transition(LifecycleState::Preparing).unwrap();
            if before_failure == LifecycleState::Starting {
                lifecycle.transition(LifecycleState::Prepared).unwrap();
                lifecycle.transition(LifecycleState::Starting).unwrap();
            }
            lifecycle.transition(LifecycleState::Failed).unwrap();
            lifecycle.transition(LifecycleState::Stopped).unwrap();
            assert_eq!(lifecycle.state(), LifecycleState::Stopped);
        }
    }

    #[test]
    fn public_state_names_match_the_invoke_contract() {
        assert_eq!(LifecycleState::Stopped.as_str(), "stopped");
        assert_eq!(LifecycleState::Preparing.as_str(), "preparing");
        assert_eq!(LifecycleState::Prepared.as_str(), "prepared");
        assert_eq!(LifecycleState::Starting.as_str(), "starting");
        assert_eq!(LifecycleState::Running.as_str(), "running");
        assert_eq!(LifecycleState::Stopping.as_str(), "stopping");
        assert_eq!(LifecycleState::Failed.as_str(), "failed");
    }
}
