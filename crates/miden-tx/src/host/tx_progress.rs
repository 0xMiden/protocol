pub use alloc::vec::Vec;

use super::{NoteId, RowIndex, TransactionMeasurements};

// TRANSACTION PROGRESS
// ================================================================================================

/// Contains the information about the number of cycles for each of the transaction execution
/// stages.
#[derive(Clone, Debug)]
pub struct TransactionProgress {
    prologue: CycleInterval,
    notes_processing: CycleInterval,
    note_execution: Vec<(NoteId, CycleInterval)>,
    tx_script_processing: CycleInterval,
    epilogue: CycleInterval,
    auth_procedure: CycleInterval,
    /// The cycle count of the processor at the point where compute_fee called clk to obtain the
    /// transaction's cycle count.
    ///
    /// This is used to get the total number of cycles the transaction takes for use in
    /// compute_fee itself.
    epilogue_after_tx_cycles_obtained: Option<RowIndex>,
}

impl TransactionProgress {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Initializes a new [`TransactionProgress`] with all values set to their defaults.
    pub fn new() -> Self {
        Self {
            prologue: CycleInterval::default(),
            notes_processing: CycleInterval::default(),
            note_execution: Vec::new(),
            tx_script_processing: CycleInterval::default(),
            epilogue: CycleInterval::default(),
            auth_procedure: CycleInterval::default(),
            epilogue_after_tx_cycles_obtained: None,
        }
    }

    // STATE ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub fn prologue(&self) -> &CycleInterval {
        &self.prologue
    }

    pub fn notes_processing(&self) -> &CycleInterval {
        &self.notes_processing
    }

    pub fn note_execution(&self) -> &Vec<(NoteId, CycleInterval)> {
        &self.note_execution
    }

    pub fn tx_script_processing(&self) -> &CycleInterval {
        &self.tx_script_processing
    }

    pub fn epilogue(&self) -> &CycleInterval {
        &self.epilogue
    }

    pub fn auth_procedure(&self) -> &CycleInterval {
        &self.auth_procedure
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    pub fn start_prologue(&mut self, cycle: RowIndex) {
        self.prologue.set_start(cycle);
    }

    pub fn end_prologue(&mut self, cycle: RowIndex) {
        self.prologue.set_end(cycle);
    }

    pub fn start_notes_processing(&mut self, cycle: RowIndex) {
        self.notes_processing.set_start(cycle);
    }

    pub fn end_notes_processing(&mut self, cycle: RowIndex) {
        self.notes_processing.set_end(cycle);
    }

    pub fn start_note_execution(&mut self, cycle: RowIndex, note_id: NoteId) {
        self.note_execution.push((note_id, CycleInterval::new(cycle)));
    }

    pub fn end_note_execution(&mut self, cycle: RowIndex) {
        if let Some((_, interval)) = self.note_execution.last_mut() {
            interval.set_end(cycle)
        }
    }

    pub fn start_tx_script_processing(&mut self, cycle: RowIndex) {
        self.tx_script_processing.set_start(cycle);
    }

    pub fn end_tx_script_processing(&mut self, cycle: RowIndex) {
        self.tx_script_processing.set_end(cycle);
    }

    pub fn start_epilogue(&mut self, cycle: RowIndex) {
        self.epilogue.set_start(cycle);
    }

    pub fn start_auth_procedure(&mut self, cycle: RowIndex) {
        self.auth_procedure.set_start(cycle);
    }

    pub fn end_auth_procedure(&mut self, cycle: RowIndex) {
        self.auth_procedure.set_end(cycle);
    }

    pub fn epilogue_after_tx_cycles_obtained(&mut self, cycle: RowIndex) {
        self.epilogue_after_tx_cycles_obtained = Some(cycle);
    }

    pub fn end_epilogue(&mut self, cycle: RowIndex) {
        self.epilogue.set_end(cycle);
    }
}

impl Default for TransactionProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl From<TransactionProgress> for TransactionMeasurements {
    fn from(tx_progress: TransactionProgress) -> Self {
        let prologue = tx_progress.prologue().len();

        let notes_processing = tx_progress.notes_processing().len();

        let note_execution = tx_progress
            .note_execution()
            .iter()
            .map(|(note_id, interval)| (*note_id, interval.len()))
            .collect();

        let tx_script_processing = tx_progress.tx_script_processing().len();

        let epilogue = tx_progress.epilogue().len();

        let auth_procedure = tx_progress.auth_procedure().len();

        // Compute the number of cycles that where not captured by the call to clk.
        let after_tx_cycles_obtained = if let Some(epilogue_after_tx_cycles_obtained) =
            tx_progress.epilogue_after_tx_cycles_obtained
        {
            tx_progress.epilogue().end().expect("epilogue end should be set")
                - epilogue_after_tx_cycles_obtained
        } else {
            0
        };

        Self {
            prologue,
            notes_processing,
            note_execution,
            tx_script_processing,
            epilogue,
            auth_procedure,
            after_tx_cycles_obtained,
        }
    }
}

/// Stores the cycles corresponding to the start and the end of an interval.
#[derive(Clone, Default, Debug)]
pub struct CycleInterval {
    start: Option<RowIndex>,
    end: Option<RowIndex>,
}

impl CycleInterval {
    pub fn new(start: RowIndex) -> Self {
        Self { start: Some(start), end: None }
    }

    pub fn set_start(&mut self, s: RowIndex) {
        self.start = Some(s);
    }

    pub fn set_end(&mut self, e: RowIndex) {
        self.end = Some(e);
    }

    pub fn start(&self) -> Option<RowIndex> {
        self.start
    }

    pub fn end(&self) -> Option<RowIndex> {
        self.end
    }

    /// Calculate the length of the interval
    pub fn len(&self) -> usize {
        // Safe, straightforward computation without relying on unstable syntax
        match (self.start, self.end) {
            (Some(start), Some(end)) if end >= start => end - start,
            _ => 0,
        }
    }
}
