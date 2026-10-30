set_option autoImplicit false

namespace ReleaseGlz.Redaction

/-- Whether the non-empty `secret` occurs in `text` at `start`. -/
def occursAt (text secret : List Nat) (start : Nat) : Bool :=
  !secret.isEmpty && secret.isPrefixOf (text.drop start)

/-- Whether an occurrence of a non-empty secret covers the byte at `index`, straight from the definition. -/
def covered (text : List Nat) (secrets : List (List Nat)) (index : Nat) : Bool :=
  secrets.any fun secret =>
    (List.range (index + 1)).any fun start =>
      occursAt text secret start && decide (index < start + secret.length)

/-- One step of the core's scan: the occurrences that start at `start` extend `acc`. -/
def extend (text : List Nat) (start : Nat) (acc : Nat) (secret : List Nat) : Nat :=
  if occursAt text secret start then max acc (start + secret.length) else acc

/-- The end of the furthest occurrence that starts before `examined`, as the core's iterator accumulates it. -/
def reach (text : List Nat) (secrets : List (List Nat)) : Nat → Nat
  | 0 => 0
  | n + 1 => secrets.foldl (extend text n) (reach text secrets n)

/-- The coverage of every byte of `text`, as the core decides it once it has examined the occurrences that start at or before the byte. -/
def coverage (text : List Nat) (secrets : List (List Nat)) : List Bool :=
  (List.range text.length).map fun index => decide (index < reach text secrets (index + 1))

/-- The maximal runs of equal values, each as its value and its length. -/
def runs : List Bool → List (Bool × Nat)
  | [] => []
  | value :: rest =>
    match runs rest with
    | [] => [(value, 1)]
    | (next, count) :: more =>
      if value = next then (value, count + 1) :: more else (value, 1) :: (next, count) :: more

/-- The values that `segments` stand for, one per byte. -/
def expand (segments : List (Bool × Nat)) : List Bool :=
  segments.flatMap fun (value, count) => List.replicate count value

/-- The segments that redaction yields for `text`: maximal runs of kept or redacted bytes. -/
def segments (text : List Nat) (secrets : List (List Nat)) : List (Bool × Nat) :=
  runs (coverage text secrets)

theorem extend_bound (text : List Nat) (start acc : Nat) (secrets : List (List Nat)) (index : Nat) :
    index < secrets.foldl (extend text start) acc ↔
      index < acc ∨ ∃ secret ∈ secrets,
        occursAt text secret start = true ∧ index < start + secret.length := by
  induction secrets generalizing acc with
  | nil => simp
  | cons secret rest ih =>
    simp only [List.foldl_cons, List.mem_cons]
    rw [ih]
    unfold extend
    by_cases occurs : occursAt text secret start = true
    · simp only [occurs, ↓reduceIte]
      constructor
      · rintro (bound | ⟨other, member, other_occurs, other_bound⟩)
        · by_cases left : index < acc
          · exact Or.inl left
          · exact Or.inr ⟨secret, Or.inl rfl, occurs, by omega⟩
        · exact Or.inr ⟨other, Or.inr member, other_occurs, other_bound⟩
      · rintro (bound | ⟨other, (rfl | member), other_occurs, other_bound⟩)
        · exact Or.inl (by omega)
        · exact Or.inl (by omega)
        · exact Or.inr ⟨other, member, other_occurs, other_bound⟩
    · simp only [occurs, Bool.false_eq_true, ↓reduceIte]
      constructor
      · rintro (bound | ⟨other, member, other_occurs, other_bound⟩)
        · exact Or.inl bound
        · exact Or.inr ⟨other, Or.inr member, other_occurs, other_bound⟩
      · rintro (bound | ⟨other, (rfl | member), other_occurs, other_bound⟩)
        · exact Or.inl bound
        · exact absurd other_occurs occurs
        · exact Or.inr ⟨other, member, other_occurs, other_bound⟩

theorem reach_bound (text : List Nat) (secrets : List (List Nat)) (examined index : Nat) :
    index < reach text secrets examined ↔
      ∃ start < examined, ∃ secret ∈ secrets,
        occursAt text secret start = true ∧ index < start + secret.length := by
  induction examined with
  | zero => simp [reach]
  | succ n ih =>
    simp only [reach]
    rw [extend_bound, ih]
    constructor
    · rintro (⟨start, bound, secret, member, occurs, covers⟩ | ⟨secret, member, occurs, covers⟩)
      · exact ⟨start, by omega, secret, member, occurs, covers⟩
      · exact ⟨n, by omega, secret, member, occurs, covers⟩
    · rintro ⟨start, bound, secret, member, occurs, covers⟩
      by_cases last : start = n
      · subst last
        exact Or.inr ⟨secret, member, occurs, covers⟩
      · exact Or.inl ⟨start, by omega, secret, member, occurs, covers⟩

/-- The core's accumulated reach decides exactly the coverage that the definition gives, for texts and secrets of every length. -/
theorem reach_decides_coverage (text : List Nat) (secrets : List (List Nat)) (index : Nat) :
    decide (index < reach text secrets (index + 1)) = covered text secrets index := by
  rw [Bool.eq_iff_iff, decide_eq_true_iff, reach_bound]
  simp only [covered, List.any_eq_true, List.mem_range, Bool.and_eq_true, decide_eq_true_eq]
  constructor
  · rintro ⟨start, bound, secret, member, occurs, covers⟩
    exact ⟨secret, member, start, bound, occurs, covers⟩
  · rintro ⟨secret, member, start, bound, occurs, covers⟩
    exact ⟨start, bound, secret, member, occurs, covers⟩

/-- Every byte that an occurrence covers is redacted, and every other byte is kept, for texts and secrets of every length. -/
theorem coverage_is_the_definition (text : List Nat) (secrets : List (List Nat)) :
    coverage text secrets = (List.range text.length).map (covered text secrets) := by
  unfold coverage
  congr 1
  funext index
  exact reach_decides_coverage text secrets index

/-- The segments stand for exactly the coverage they came from, so they cover every byte once and in order. -/
theorem segments_cover_every_byte_once (flags : List Bool) : expand (runs flags) = flags := by
  induction flags with
  | nil => rfl
  | cons value rest ih =>
    unfold runs
    split
    · rename_i nothing
      rw [nothing] at ih
      simp [expand] at ih ⊢
      exact ih
    · rename_i next count more same
      rw [same] at ih
      split
      · rename_i equal
        subst equal
        simp only [expand, List.flatMap_cons, List.replicate_succ, List.cons_append] at ih ⊢
        rw [ih]
      · simp only [expand, List.flatMap_cons, List.replicate_one, List.singleton_append] at ih ⊢
        rw [ih]

/-- Every segment holds at least one byte. -/
theorem segments_are_nonempty (flags : List Bool) : ∀ segment ∈ runs flags, 0 < segment.2 := by
  induction flags with
  | nil => simp [runs]
  | cons value rest ih =>
    intro segment member
    unfold runs at member
    split at member
    · simp at member
      rw [member]
      omega
    · rename_i next count more same
      rw [same] at ih
      split at member
      · simp only [List.mem_cons] at member
        rcases member with rfl | member
        · omega
        · exact ih segment (List.mem_cons_of_mem _ member)
      · simp only [List.mem_cons] at member
        rcases member with rfl | rfl | member
        · omega
        · exact ih _ (List.mem_cons_self ..)
        · exact ih segment (List.mem_cons_of_mem _ member)

/-- Whether every segment differs in value from the one after it. -/
def alternating : List (Bool × Nat) → Bool
  | [] => true
  | [_] => true
  | first :: second :: rest => first.1 != second.1 && alternating (second :: rest)

/-- Neighboring segments differ, so each maximal covered run becomes one redacted segment. -/
theorem neighboring_segments_differ (flags : List Bool) : alternating (runs flags) = true := by
  induction flags with
  | nil => rfl
  | cons value rest ih =>
    unfold runs
    split
    · rfl
    · rename_i next count more same
      rw [same] at ih
      split
      · rename_i equal
        subst equal
        cases more with
        | nil => rfl
        | cons third more => simpa [alternating] using ih
      · rename_i different
        simp [alternating, ih, different]

#print axioms reach_decides_coverage
#print axioms coverage_is_the_definition
#print axioms segments_cover_every_byte_once
#print axioms segments_are_nonempty
#print axioms neighboring_segments_differ

end ReleaseGlz.Redaction
