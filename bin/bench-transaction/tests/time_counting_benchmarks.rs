#![cfg(feature = "concurrent")]

// Exercise the actual Criterion benchmark helpers under the integration-test harness.
#[allow(dead_code)]
mod timing {
    include!("../src/time_counting_benchmarks/prove.rs");

    #[cfg(test)]
    mod tests {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        use miden_protocol::Word;
        use miden_standards::code_builder::CodeBuilder;

        use super::*;

        fn transaction(fail: bool) -> Result<MockTransaction> {
            let mut tx = tx_consume_single_p2id_note_falcon()?;
            if fail {
                let script = CodeBuilder::default().compile_tx_script(
                    r#"
                    @transaction_script
                    pub proc main
                        push.0 assert.err="timing regression fixture"
                    end
                    "#,
                )?;
                tx.set_tx_args(
                    tx.tx_args().clone().with_tx_script_and_args(script, Word::default()),
                );
            }
            Ok(tx)
        }

        fn criterion() -> Criterion {
            Criterion::default()
                .sample_size(10)
                .warm_up_time(Duration::from_millis(1))
                .measurement_time(Duration::from_millis(1))
                .without_plots()
        }

        #[test]
        fn successful_execution_still_returns_timing_samples() {
            let mut criterion = criterion();
            criterion.bench_function("timing-success-control", |b| {
                bench_async_execute(b, || async { transaction(false) });
            });
        }

        #[test]
        fn failed_execution_aborts_timing_samples() {
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let failure = runtime.block_on(transaction(true).unwrap().execute()).unwrap_err();
            assert!(format!("{failure:?}").contains("timing regression fixture"));

            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut criterion = criterion();
                criterion.bench_function("timing-execution-error", |b| {
                    bench_async_execute(b, || async { transaction(true) });
                });
            }));
            let panic = result.expect_err("failed execution was accepted as a timing sample");
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("");
            assert!(message.contains("execute failed"), "unexpected panic: {message}");
        }
    }
}
