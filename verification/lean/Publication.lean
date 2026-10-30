set_option autoImplicit false

namespace ReleaseGlz

inductive Presence where
  | absent
  | pending
  | matches
  | differs
  deriving DecidableEq, Repr

inductive Decision where
  | create
  | keep
  | conflict
  deriving DecidableEq, Repr

structure Obj where
  wanted : Bool
  presence : Presence
  blocking : Bool
  deriving DecidableEq, Repr

def decision (o : Obj) : Decision :=
  match o.wanted, o.presence with
  | _, .differs => .conflict
  | false, .pending => .conflict
  | false, .matches => .conflict
  | true, .absent => .create
  | true, .pending => .create
  | true, .matches => .keep
  | false, .absent => .keep

inductive State where
  | released
  | partiallyReleased
  | candidateReady
  deriving DecidableEq, Repr

inductive Outcome where
  | conflict (index : Nat)
  | awaitingApproval
  | proceed (state : State) (effects : List Nat)
  deriving DecidableEq, Repr

def firstConflict : Nat → List Obj → Option Nat
  | _, [] => none
  | i, o :: rest => if decision o = .conflict then some i else firstConflict (i + 1) rest

def effectsFrom : Nat → List Obj → List Nat
  | _, [] => []
  | i, o :: rest =>
    if decision o = .create then i :: effectsFrom (i + 1) rest else effectsFrom (i + 1) rest

def effects (objects : List Obj) : List Nat :=
  effectsFrom 0 objects

def blockingEffect (o : Obj) : Bool :=
  decide (decision o = .create) && o.blocking

def present (o : Obj) : Bool :=
  decide (o.presence ≠ .absent)

def stateOf (objects : List Obj) : State :=
  if objects.any blockingEffect then
    if objects.any present then .partiallyReleased else .candidateReady
  else .released

def reconcile (objects : List Obj) (approved : Bool) : Outcome :=
  match firstConflict 0 objects with
  | some index => .conflict index
  | none => if approved then .proceed (stateOf objects) (effects objects) else .awaitingApproval

/-- The object at `index` as a release leaves it after publishing it. -/
def publish (objects : List Obj) (index : Nat) : List Obj :=
  match objects[index]? with
  | some o => objects.set index { o with presence := .matches }
  | none => objects

theorem create_means_missing (o : Obj) (h : decision o = .create) :
    o.wanted = true ∧ (o.presence = .absent ∨ o.presence = .pending) := by
  rcases o with ⟨wanted, presence, blocking⟩
  cases wanted <;> cases presence <;> simp_all [decision]

theorem conflict_iff_differs (o : Obj) :
    decision o = .conflict ↔ (o.presence = .differs ∨ (o.wanted = false ∧ o.presence ≠ .absent)) := by
  rcases o with ⟨wanted, presence, blocking⟩
  cases wanted <;> cases presence <;> simp [decision]

theorem mem_effectsFrom (start : Nat) (objects : List Obj) (index : Nat)
    (h : index ∈ effectsFrom start objects) :
    start ≤ index ∧ ∃ o, objects[index - start]? = some o ∧ decision o = .create := by
  induction objects generalizing start with
  | nil => simp [effectsFrom] at h
  | cons o rest ih =>
    simp only [effectsFrom] at h
    split at h
    · rcases List.mem_cons.mp h with rfl | tail
      · exact ⟨Nat.le_refl _, o, by simp, by assumption⟩
      · obtain ⟨bound, o', found, created⟩ := ih (start + 1) tail
        refine ⟨by omega, o', ?_, created⟩
        have shift : index - start = (index - (start + 1)) + 1 := by omega
        rw [shift]
        simpa using found
    · obtain ⟨bound, o', found, created⟩ := ih (start + 1) h
      refine ⟨by omega, o', ?_, created⟩
      have shift : index - start = (index - (start + 1)) + 1 := by omega
      rw [shift]
      simpa using found

/-- Every effect concerns an object that the Candidate wants and the world lacks or holds pending. -/
theorem effect_concerns_missing_object (objects : List Obj) (index : Nat)
    (h : index ∈ effects objects) :
    ∃ o, objects[index]? = some o ∧ o.wanted = true ∧
      (o.presence = .absent ∨ o.presence = .pending) := by
  obtain ⟨_, o, found, created⟩ := mem_effectsFrom 0 objects index h
  exact ⟨o, by simpa using found, create_means_missing o created⟩

theorem firstConflict_none (start : Nat) (objects : List Obj)
    (h : firstConflict start objects = none) : ∀ o ∈ objects, decision o ≠ .conflict := by
  induction objects generalizing start with
  | nil => simp
  | cons o rest ih =>
    simp only [firstConflict] at h
    split at h
    · simp at h
    · intro o' member
      rcases List.mem_cons.mp member with rfl | tail
      · assumption
      · exact ih (start + 1) h o' tail

/-- Any object that differs from the Candidate stops the release with a conflict, whatever the approval. -/
theorem differing_object_conflicts (objects : List Obj) (approved : Bool) (o : Obj)
    (member : o ∈ objects)
    (differs : o.presence = .differs ∨ (o.wanted = false ∧ o.presence ≠ .absent)) :
    ∃ index, reconcile objects approved = .conflict index := by
  have conflicting : decision o = .conflict := (conflict_iff_differs o).mpr differs
  unfold reconcile
  cases found : firstConflict 0 objects with
  | some index => exact ⟨index, rfl⟩
  | none => exact absurd conflicting (firstConflict_none 0 objects found o member)

/-- Without approval, no effect leaves the reconciler. -/
theorem no_effect_without_approval (objects : List Obj) (state : State) (planned : List Nat) :
    reconcile objects false ≠ .proceed state planned := by
  unfold reconcile
  cases firstConflict 0 objects <;> simp

theorem length_effectsFrom (start : Nat) (objects : List Obj) :
    (effectsFrom start objects).length ≤ objects.length := by
  induction objects generalizing start with
  | nil => simp [effectsFrom]
  | cons o rest ih =>
    simp only [effectsFrom]
    split
    · simpa using ih (start + 1)
    · exact Nat.le_succ_of_le (ih (start + 1))

/-- A plan never lists more effects than the release has objects. -/
theorem effects_within_objects (objects : List Obj) :
    (effects objects).length ≤ objects.length :=
  length_effectsFrom 0 objects

theorem start_le_of_mem (start : Nat) (objects : List Obj) (index : Nat)
    (h : index ∈ effectsFrom start objects) : start ≤ index :=
  (mem_effectsFrom start objects index h).1

theorem effectsFrom_set (start : Nat) (objects : List Obj) (index : Nat) (o : Obj)
    (found : objects[index]? = some o) (created : decision o = .create) :
    effectsFrom start (objects.set index { o with presence := .matches }) =
      (effectsFrom start objects).erase (start + index) := by
  induction objects generalizing start index with
  | nil => simp at found
  | cons head rest ih =>
    cases index with
    | zero =>
      simp at found
      subst found
      have kept : decision { head with presence := .matches } = .keep := by
        obtain ⟨wanted, _⟩ := create_means_missing head created
        rcases head with ⟨w, p, b⟩
        simp at wanted
        subst wanted
        simp [decision]
      simp [effectsFrom, kept, created]
    | succ index =>
      simp at found
      have step := ih (start + 1) index found
      simp only [List.set_cons_succ, effectsFrom]
      have shift : start + 1 + index = start + (index + 1) := by omega
      rw [step, shift]
      split
      · rw [List.erase_cons]
        have different : (start == start + (index + 1)) = false := by
          simp
        simp [different]
      · rfl

/-- Publishing the object of one effect removes exactly that effect from the next plan and adds none. -/
theorem publishing_removes_exactly_that_effect (objects : List Obj) (index : Nat)
    (h : index ∈ effects objects) :
    effects (publish objects index) = (effects objects).erase index := by
  obtain ⟨_, o, found, created⟩ := mem_effectsFrom 0 objects index h
  simp at found
  unfold publish effects
  rw [found]
  simpa using effectsFrom_set 0 objects index o found created

/-- Each published effect shortens the plan by one, so a run needs at most as many attempts as its first plan has effects. -/
theorem publishing_shortens_the_plan (objects : List Obj) (index : Nat)
    (h : index ∈ effects objects) :
    (effects (publish objects index)).length + 1 = (effects objects).length := by
  rw [publishing_removes_exactly_that_effect objects index h, List.length_erase_of_mem h]
  have : 0 < (effects objects).length := List.length_pos_of_mem h
  omega

/-- A release counts as released exactly when no blocking effect remains. -/
theorem released_iff_no_blocking_effect (objects : List Obj) :
    stateOf objects = .released ↔ ∀ o ∈ objects, blockingEffect o = false := by
  unfold stateOf
  by_cases blocking : objects.any blockingEffect = true
  · simp only [blocking, ↓reduceIte]
    constructor
    · intro h
      split at h <;> cases h
    · intro none
      obtain ⟨o, member, holds⟩ := List.any_eq_true.mp blocking
      rw [none o member] at holds
      cases holds
  · simp only [Bool.not_eq_true] at blocking
    simp only [blocking, Bool.false_eq_true, ↓reduceIte, true_iff]
    intro o member
    have absent := List.any_eq_false.mp blocking o member
    simpa using absent

#print axioms create_means_missing
#print axioms conflict_iff_differs
#print axioms effect_concerns_missing_object
#print axioms differing_object_conflicts
#print axioms no_effect_without_approval
#print axioms effects_within_objects
#print axioms publishing_removes_exactly_that_effect
#print axioms publishing_shortens_the_plan
#print axioms released_iff_no_blocking_effect

end ReleaseGlz
