set_option autoImplicit false

namespace ReleaseGlz.Marker

/-- The bytes of `<!-- release-glz:managed `, which open a marker. -/
def markerPrefix : List Nat :=
  [60, 33, 45, 45, 32, 114, 101, 108, 101, 97, 115, 101, 45, 103, 108, 122, 58, 109, 97, 110, 97,
    103, 101, 100, 32]

/-- The bytes of ` -->`, which close a marker. -/
def markerSuffix : List Nat := [32, 45, 45, 62]

/-- The byte of `<`. -/
def lessThan : Nat := 60

/-- The bytes of `&lt;`, which inert text writes for `<`. -/
def escaped : List Nat := [38, 108, 116, 59]

/-- Text with every `<` written as `&lt;`. -/
def inert : List Nat → List Nat
  | [] => []
  | byte :: rest => (if byte = lessThan then escaped else [byte]) ++ inert rest

/-- Inert text holds no `<`, so it can't open a marker, a comment, or a tag. -/
theorem inert_holds_no_less_than (text : List Nat) : lessThan ∉ inert text := by
  induction text with
  | nil => simp [inert]
  | cons byte rest ih =>
    simp only [inert, List.mem_append, not_or]
    refine ⟨?_, ih⟩
    by_cases h : byte = lessThan
    · simp [h, escaped, lessThan]
    · simp only [h, ↓reduceIte, List.mem_singleton]
      exact fun same => h same.symm

/-- Whether `needle` occurs in `haystack` from `offset` on. -/
def occursAt (haystack needle : List Nat) (offset : Nat) : Bool :=
  needle.isPrefixOf (haystack.drop offset)

/-- The first of the `fuel` offsets from `offset` on where `needle` occurs. -/
def firstFrom (haystack needle : List Nat) (offset : Nat) : Nat → Option Nat
  | 0 => none
  | fuel + 1 =>
    if occursAt haystack needle offset then some offset
    else firstFrom haystack needle (offset + 1) fuel

/-- The last offset up to `offset` where `needle` occurs. -/
def lastFrom (haystack needle : List Nat) : Nat → Option Nat
  | 0 => if occursAt haystack needle 0 then some 0 else none
  | offset + 1 =>
    if occursAt haystack needle (offset + 1) then some (offset + 1)
    else lastFrom haystack needle offset

/-- The first offset where `needle` fits and occurs in `haystack`, as the core searches. -/
def firstOccurrence (haystack needle : List Nat) : Option Nat :=
  if needle.length ≤ haystack.length then
    firstFrom haystack needle 0 (haystack.length - needle.length + 1)
  else none

/-- The last offset where `needle` fits and occurs in `haystack`, as the core searches. -/
def lastOccurrence (haystack needle : List Nat) : Option Nat :=
  if needle.length ≤ haystack.length then lastFrom haystack needle (haystack.length - needle.length)
  else none

/-- The offset of the marker that ends a trimmed `body`, when no other marker starts before it. -/
def markerStart (body : List Nat) : Option Nat :=
  match lastOccurrence body markerPrefix with
  | none => none
  | some start =>
    match firstOccurrence (body.drop start) markerSuffix with
    | none => none
    | some rel =>
      if firstOccurrence (body.take start) markerPrefix = none ∧
          start + rel + markerSuffix.length = body.length then
        some start
      else none

/-- Whether `a` is immediately followed by `b` somewhere in `l`. -/
def hasPair (a b : Nat) : List Nat → Bool
  | x :: y :: rest => (x == a && y == b) || hasPair a b (y :: rest)
  | _ => false

theorem hasPair_append (a b : Nat) (l t : List Nat) :
    hasPair a b (l ++ t) =
      (hasPair a b l || hasPair a b t || (l.getLast? == some a && t.head? == some b)) := by
  induction l with
  | nil => simp [hasPair]
  | cons x rest ih =>
    cases rest with
    | nil =>
      cases t with
      | nil => simp [hasPair]
      | cons y t' => simp [hasPair, Bool.or_comm]
    | cons y rest' =>
      simp only [List.cons_append, hasPair] at ih ⊢
      rw [ih]
      simp only [List.getLast?_cons_cons]
      cases (x == a && y == b) <;> simp

theorem hasPair_of_not_mem (a b : Nat) (l : List Nat) (h : a ∉ l) : hasPair a b l = false := by
  induction l with
  | nil => rfl
  | cons x rest ih =>
    cases rest with
    | nil => rfl
    | cons y rest' =>
      simp only [List.mem_cons, not_or] at h ih
      simp only [hasPair, ih h.2, Bool.or_false]
      have : (x == a) = false := by simpa [beq_iff_eq] using fun same => h.1 same.symm
      simp [this]

theorem hasPair_drop (a b : Nat) (l : List Nat) (n : Nat) (h : hasPair a b l = false) :
    hasPair a b (l.drop n) = false := by
  induction n generalizing l with
  | zero => simpa using h
  | succ n ih =>
    cases l with
    | nil => simp [hasPair]
    | cons x rest =>
      simp only [List.drop_succ_cons]
      apply ih
      cases rest with
      | nil => rfl
      | cons y rest' =>
        simp only [hasPair, Bool.or_eq_false_iff] at h
        exact h.2

/-- A list without `a` after its first byte has a pair `a`, `b` only at its front. -/
theorem hasPair_cons_of_not_mem (a b x : Nat) (rest : List Nat) (h : a ∉ rest) :
    hasPair a b (x :: rest) = (x == a && rest.head? == some b) := by
  cases rest with
  | nil => simp [hasPair]
  | cons y rest' =>
    simp only [hasPair, hasPair_of_not_mem a b (y :: rest') h, Bool.or_false, List.head?_cons]
    cases (x == a) <;> simp

theorem lastFrom_eq_some (haystack needle : List Nat) (limit p : Nat) (hp : p ≤ limit)
    (occurs : occursAt haystack needle p = true)
    (after : ∀ q, p < q → q ≤ limit → occursAt haystack needle q = false) :
    lastFrom haystack needle limit = some p := by
  induction limit with
  | zero =>
    have zero : p = 0 := by omega
    subst zero
    simp [lastFrom, occurs]
  | succ n ih =>
    by_cases last : p = n + 1
    · subst last
      simp [lastFrom, occurs]
    · have skipped : occursAt haystack needle (n + 1) = false :=
        after (n + 1) (by omega) (Nat.le_refl _)
      simp only [lastFrom, skipped, Bool.false_eq_true, ↓reduceIte]
      exact ih (by omega) (fun q later bound => after q later (by omega))

theorem firstFrom_eq_some (haystack needle : List Nat) (start fuel p : Nat) (low : start ≤ p)
    (high : p < start + fuel) (occurs : occursAt haystack needle p = true)
    (before : ∀ q, start ≤ q → q < p → occursAt haystack needle q = false) :
    firstFrom haystack needle start fuel = some p := by
  induction fuel generalizing start with
  | zero => omega
  | succ n ih =>
    by_cases here : start = p
    · subst here
      simp [firstFrom, occurs]
    · have skipped : occursAt haystack needle start = false :=
        before start (Nat.le_refl _) (by omega)
      simp only [firstFrom, skipped, Bool.false_eq_true, ↓reduceIte]
      exact ih (start + 1) (by omega) (by omega) (fun q low' high' => before q (by omega) high')

theorem firstFrom_eq_none (haystack needle : List Nat) (start fuel : Nat)
    (never : ∀ q, start ≤ q → q < start + fuel → occursAt haystack needle q = false) :
    firstFrom haystack needle start fuel = none := by
  induction fuel generalizing start with
  | zero => rfl
  | succ n ih =>
    have skipped := never start (Nat.le_refl _) (by omega)
    simp only [firstFrom, skipped, Bool.false_eq_true, ↓reduceIte]
    exact ih (start + 1) (fun q low high => never q (by omega) (by omega))

theorem occursAt_iff (haystack needle : List Nat) (p : Nat) :
    occursAt haystack needle p = true ↔ ∃ rest, haystack.drop p = needle ++ rest := by
  unfold occursAt
  rw [List.isPrefixOf_iff_prefix]
  constructor
  · rintro ⟨rest, eq⟩
    exact ⟨rest, eq.symm⟩
  · rintro ⟨rest, eq⟩
    exact ⟨rest, eq.symm⟩

/-- An occurrence of `needle` puts the pair at the front of `needle.drop i` into the haystack `i` bytes after the occurrence. -/
theorem hasPair_of_occursAt (haystack needle : List Nat) (p i a b : Nat) (rest : List Nat)
    (occurs : occursAt haystack needle p = true) (pair : needle.drop i = a :: b :: rest) :
    hasPair a b (haystack.drop (p + i)) = true := by
  obtain ⟨tail, eq⟩ := (occursAt_iff haystack needle p).mp occurs
  have short : i ≤ needle.length := by
    have := congrArg List.length pair
    simp only [List.length_drop, List.length_cons] at this
    omega
  have shifted : haystack.drop (p + i) = (needle ++ tail).drop i := by
    rw [← eq, List.drop_drop]
  rw [shifted, List.drop_append_of_le_length short, pair]
  simp [hasPair]

/-- The byte of a space, which separates the fields of a marker. -/
def space : Nat := 32

/-- The byte of `=`, which separates a key from its value. -/
def equals : Nat := 61

/-- The keys of a marker, in the order release-glz writes them. -/
def packageKey : List Nat := [112, 97, 99, 107, 97, 103, 101]
def branchKey : List Nat := [98, 114, 97, 110, 99, 104]
def headKey : List Nat := [104, 101, 97, 100]
def digestKey : List Nat := [100, 105, 103, 101, 115, 116]
def versionKey : List Nat := [118, 101, 114, 115, 105, 111, 110]
def intentKey : List Nat := [105, 110, 116, 101, 110, 116]

/-- The values of the fields of a marker. -/
structure Values where
  package : List Nat
  branch : List Nat
  head : List Nat
  digest : List Nat
  version : List Nat
  intent : List Nat
  deriving DecidableEq, Repr

/-- A field after the first: a space, the key, `=`, and the value. -/
def segment (key value : List Nat) : List Nat := space :: (key ++ equals :: value)

/-- The fields of a marker, separated by spaces. -/
def fields (values : Values) : List Nat :=
  packageKey ++ equals :: values.package ++ segment branchKey values.branch ++
    segment headKey values.head ++ segment digestKey values.digest ++
    segment versionKey values.version ++ segment intentKey values.intent

/-- The marker that holds `values`, as the core writes it. -/
def render (values : Values) : List Nat := markerPrefix ++ fields values ++ markerSuffix

/-- No value holds a space, which every value that release-glz writes satisfies. -/
def Spaceless (values : Values) : Prop :=
  space ∉ values.package ∧ space ∉ values.branch ∧ space ∉ values.head ∧
    space ∉ values.digest ∧ space ∉ values.version ∧ space ∉ values.intent

theorem segment_hasPair (b : Nat) (key value : List Nat) (keyless : space ∉ key)
    (valueless : space ∉ value) :
    hasPair space b (segment key value) = ((key ++ equals :: value).head? == some b) := by
  unfold segment
  rw [hasPair_cons_of_not_mem]
  · simp
  · simp only [List.mem_append, List.mem_cons, not_or]
    exact ⟨keyless, by decide, valueless⟩

/-- In the fields of a marker, a space is never followed by `b` when no key starts with `b`. -/
theorem fields_hasPair (b : Nat) (values : Values) (spaceless : Spaceless values)
    (notSpace : b ≠ space) (branch : branchKey.head? ≠ some b) (head : headKey.head? ≠ some b)
    (digest : digestKey.head? ≠ some b) (version : versionKey.head? ≠ some b)
    (intent : intentKey.head? ≠ some b) :
    hasPair space b (fields values) = false := by
  obtain ⟨package', branch', head', digest', version', intent'⟩ := spaceless
  have first : hasPair space b (packageKey ++ equals :: values.package) = false := by
    apply hasPair_of_not_mem
    simp only [List.mem_append, List.mem_cons, not_or]
    exact ⟨by decide, by decide, package'⟩
  have keyless : ∀ key : List Nat, key ∈ [branchKey, headKey, digestKey, versionKey, intentKey] →
      space ∉ key := by decide
  have segmentFree : ∀ key value, space ∉ key → space ∉ value → key.head? ≠ some b →
      key ≠ [] → hasPair space b (segment key value) = false := by
    intro key value keyFree valueFree start nonempty
    rw [segment_hasPair b key value keyFree valueFree]
    cases key with
    | nil => exact absurd rfl nonempty
    | cons k rest => simpa using start
  have boundary : ∀ (l : List Nat) (key value : List Nat),
      (l.getLast? == some space && (segment key value).head? == some b) = false := by
    intro l key value
    simp [segment, notSpace.symm]
  unfold fields
  simp only [hasPair_append, first, boundary, Bool.or_false, Bool.false_or]
  simp only [segmentFree branchKey values.branch (keyless _ (by decide)) branch' branch (by decide),
    segmentFree headKey values.head (keyless _ (by decide)) head' head (by decide),
    segmentFree digestKey values.digest (keyless _ (by decide)) digest' digest (by decide),
    segmentFree versionKey values.version (keyless _ (by decide)) version' version (by decide),
    segmentFree intentKey values.intent (keyless _ (by decide)) intent' intent (by decide),
    Bool.or_self]

theorem occursAt_append_right (text rest needle : List Nat) (q : Nat) (h : text.length ≤ q) :
    occursAt (text ++ rest) needle q = occursAt rest needle (q - text.length) := by
  unfold occursAt
  rw [List.drop_append, List.drop_eq_nil_of_le h, List.nil_append]

theorem fields_head (values : Values) : (fields values).head? = some 112 := by
  simp [fields, packageKey]

theorem prefix_hasPair_after_first_space (values : Values) (spaceless : Spaceless values) :
    hasPair space 114 ((render values).drop 5) = false := by
  have fieldsFree := fields_hasPair 114 values spaceless (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide)
  unfold render
  rw [List.append_assoc, List.drop_append_of_le_length (by decide)]
  simp only [hasPair_append, fieldsFree, List.head?_append, fields_head]
  simp [hasPair, markerSuffix, markerPrefix, space]

/-- A marker that release-glz renders holds the start of a marker only at its own start. -/
theorem prefix_occurs_only_at_the_start (values : Values) (spaceless : Spaceless values) (q : Nat)
    (later : 0 < q) : occursAt (render values) markerPrefix q = false := by
  cases occurs : occursAt (render values) markerPrefix q with
  | false => rfl
  | true =>
    have pair := hasPair_of_occursAt (render values) markerPrefix q 4 space 114
      (markerPrefix.drop 6) occurs (by decide)
    have shifted : (render values).drop (q + 4) = ((render values).drop 5).drop (q - 1) := by
      rw [List.drop_drop]
      congr 1
      omega
    rw [shifted, hasPair_drop space 114 _ (q - 1)
      (prefix_hasPair_after_first_space values spaceless)] at pair
    exact absurd pair (by decide)

theorem render_length (values : Values) :
    (render values).length = markerPrefix.length + (fields values).length + markerSuffix.length := by
  simp only [render, List.length_append]

/-- The end of a marker that release-glz renders is the first end of a marker in it. -/
theorem suffix_occurs_first_at_the_end (values : Values) (spaceless : Spaceless values) :
    firstOccurrence (render values) markerSuffix =
      some (markerPrefix.length + (fields values).length) := by
  have fieldsFree := fields_hasPair 45 values spaceless (by decide) (by decide) (by decide)
    (by decide) (by decide) (by decide)
  have leading : hasPair space 45 (markerPrefix ++ fields values) = false := by
    simp only [hasPair_append, fieldsFree, fields_head]
    decide
  have lengths := render_length values
  have suffixLength : markerSuffix.length = 4 := rfl
  have fits : markerSuffix.length ≤ (render values).length := by omega
  simp only [firstOccurrence, fits, ↓reduceIte]
  apply firstFrom_eq_some _ _ 0 _ _ (Nat.zero_le _) (by omega)
  · rw [occursAt_iff]
    refine ⟨[], ?_⟩
    unfold render
    rw [List.drop_append, List.drop_eq_nil_of_le (by simp), List.nil_append]
    simp
  · intro q _ before
    cases occurs : occursAt (render values) markerSuffix q with
    | false => rfl
    | true =>
      obtain ⟨tail, eq⟩ := (occursAt_iff _ _ _).mp occurs
      have inside : q < (markerPrefix ++ fields values).length := by
        rw [List.length_append]
        exact before
      have split : (render values).drop q =
          (markerPrefix ++ fields values).drop q ++ markerSuffix := by
        unfold render
        rw [List.drop_append_of_le_length (Nat.le_of_lt inside)]
      rw [split] at eq
      have dropped := hasPair_drop space 45 _ q leading
      have nonempty : ((markerPrefix ++ fields values).drop q).length ≠ 0 := by
        rw [List.length_drop]
        omega
      generalize (markerPrefix ++ fields values).drop q = rest at eq dropped nonempty
      cases rest with
      | nil => exact absurd rfl nonempty
      | cons x rest' =>
        cases rest' with
        | nil => simp [markerSuffix] at eq
        | cons y rest'' =>
          simp only [markerSuffix, List.cons_append, List.cons.injEq] at eq
          obtain ⟨first, second, _⟩ := eq
          subst first second
          simp [hasPair, space] at dropped

/-- Text without `<` holds the start of no marker. -/
theorem text_holds_no_prefix (text rest : List Nat) (clean : lessThan ∉ text) (q : Nat)
    (inside : q < text.length) : occursAt (text ++ rest) markerPrefix q = false := by
  cases occurs : occursAt (text ++ rest) markerPrefix q with
  | false => rfl
  | true =>
    obtain ⟨tail, eq⟩ := (occursAt_iff _ _ _).mp occurs
    rw [List.drop_append_of_le_length (Nat.le_of_lt inside),
      List.drop_eq_getElem_cons inside] at eq
    simp only [markerPrefix, List.cons_append, List.cons.injEq] at eq
    have mem := List.getElem_mem inside
    rw [eq.1] at mem
    exact absurd mem clean

theorem firstOccurrence_prefix_of_clean (text : List Nat) (clean : lessThan ∉ text) :
    firstOccurrence text markerPrefix = none := by
  unfold firstOccurrence
  split
  · apply firstFrom_eq_none
    intro q _ bound
    have prefixLength : markerPrefix.length = 25 := rfl
    have := text_holds_no_prefix text [] clean q (by omega)
    rwa [List.append_nil] at this
  · rfl

/-- A marker that release-glz renders after text without `<` is the one marker that ends the body. -/
theorem a_rendered_marker_ends_the_body (text : List Nat) (values : Values)
    (clean : lessThan ∉ text) (spaceless : Spaceless values) :
    markerStart (text ++ render values) = some text.length := by
  have lengths := render_length values
  have prefixLength : markerPrefix.length = 25 := rfl
  have suffixLength : markerSuffix.length = 4 := rfl
  have last : lastOccurrence (text ++ render values) markerPrefix = some text.length := by
    have fits : markerPrefix.length ≤ (text ++ render values).length := by
      rw [List.length_append]
      omega
    simp only [lastOccurrence, fits, ↓reduceIte]
    apply lastFrom_eq_some _ _ _ _ (by rw [List.length_append]; omega)
    · rw [occursAt_append_right _ _ _ _ (Nat.le_refl _), Nat.sub_self, occursAt_iff]
      exact ⟨fields values ++ markerSuffix, by simp [render]⟩
    · intro q later _
      rw [occursAt_append_right _ _ _ _ (Nat.le_of_lt later)]
      exact prefix_occurs_only_at_the_start values spaceless _ (by omega)
  have suffix := suffix_occurs_first_at_the_end values spaceless
  have before := firstOccurrence_prefix_of_clean text clean
  simp only [markerStart, last, List.drop_left, suffix, List.take_left, before, true_and,
    List.length_append]
  split
  · rfl
  · omega

/-- A body in which the start of a marker comes before a rendered marker has no marker. -/
theorem an_earlier_marker_is_refused (between : List Nat) (values : Values)
    (spaceless : Spaceless values) :
    markerStart (markerPrefix ++ between ++ render values) = none := by
  have lengths := render_length values
  have prefixLength : markerPrefix.length = 25 := rfl
  have last : lastOccurrence (markerPrefix ++ between ++ render values) markerPrefix =
      some (markerPrefix ++ between).length := by
    have fits : markerPrefix.length ≤ (markerPrefix ++ between ++ render values).length := by
      simp only [List.length_append]
      omega
    simp only [lastOccurrence, fits, ↓reduceIte]
    apply lastFrom_eq_some _ _ _ _ (by simp only [List.length_append]; omega)
    · rw [occursAt_append_right _ _ _ _ (Nat.le_refl _), Nat.sub_self, occursAt_iff]
      exact ⟨fields values ++ markerSuffix, by simp [render]⟩
    · intro q later _
      rw [occursAt_append_right _ _ _ _ (Nat.le_of_lt later)]
      exact prefix_occurs_only_at_the_start values spaceless _ (by omega)
  have early : firstOccurrence (markerPrefix ++ between) markerPrefix = some 0 := by
    have fits : markerPrefix.length ≤ (markerPrefix ++ between).length := by
      simp only [List.length_append]
      omega
    simp only [firstOccurrence, fits, ↓reduceIte]
    apply firstFrom_eq_some _ _ 0 _ 0 (Nat.le_refl _) (by omega)
    · rw [occursAt_iff]
      exact ⟨between, by simp⟩
    · intro q low high
      omega
  simp only [markerStart, last, List.take_left, early]
  split <;> simp

/-- The pieces of `l` between spaces, the first of them possibly empty. -/
def splitAll : List Nat → List (List Nat)
  | [] => [[]]
  | byte :: rest =>
    if byte = space then [] :: splitAll rest
    else
      match splitAll rest with
      | [] => [[byte]]
      | first :: others => (byte :: first) :: others

/-- The nonempty pieces of `l` between spaces, as the adapter splits fields whose only whitespace is spaces. -/
def splitSpaces (l : List Nat) : List (List Nat) := (splitAll l).filter (· ≠ [])

/-- The key and the value of a field, split at its first `=`. -/
def splitField : List Nat → Option (List Nat × List Nat)
  | [] => none
  | byte :: rest =>
    if byte = equals then some ([], rest)
    else (splitField rest).map fun (key, value) => (byte :: key, value)

/-- The position of `key` among the keys of a marker. -/
def slotOf (key : List Nat) : Option Nat :=
  if key = packageKey then some 0
  else if key = branchKey then some 1
  else if key = headKey then some 2
  else if key = digestKey then some 3
  else if key = versionKey then some 4
  else if key = intentKey then some 5
  else none

/-- Record each field under its key, refusing a field without `=`, an unknown key, and a key seen before. -/
def recordAll : List (List Nat) → List (Option (List Nat)) → Option (List (Option (List Nat)))
  | [], slots => some slots
  | field :: rest, slots =>
    match splitField field with
    | none => none
    | some (key, value) =>
      match slotOf key with
      | none => none
      | some slot =>
        if (slots.getD slot none).isSome then none
        else recordAll rest (slots.set slot (some value))

/-- The values of a marker whose fields are `fieldList`, when they name each key exactly once and nothing else. -/
def markerValues (fieldList : List (List Nat)) : Option Values :=
  match recordAll fieldList [none, none, none, none, none, none] with
  | some [some package, some branch, some head, some digest, some version, some intent] =>
    some ⟨package, branch, head, digest, version, intent⟩
  | _ => none

theorem splitAll_of_not_mem (l : List Nat) (h : space ∉ l) : splitAll l = [l] := by
  induction l with
  | nil => rfl
  | cons byte rest ih =>
    simp only [List.mem_cons, not_or] at h
    simp only [splitAll, Ne.symm h.1, ↓reduceIte, ih h.2]

theorem splitAll_append_space (l t : List Nat) (h : space ∉ l) :
    splitAll (l ++ space :: t) = l :: splitAll t := by
  induction l with
  | nil => simp [splitAll]
  | cons byte rest ih =>
    simp only [List.mem_cons, not_or] at h
    simp only [List.cons_append, splitAll, Ne.symm h.1, ↓reduceIte, ih h.2]

theorem splitField_key (key value : List Nat) (h : equals ∉ key) :
    splitField (key ++ equals :: value) = some (key, value) := by
  induction key with
  | nil => simp [splitField]
  | cons byte rest ih =>
    simp only [List.mem_cons, not_or] at h
    simp only [List.cons_append, splitField, Ne.symm h.1, ↓reduceIte, ih h.2, Option.map_some]

theorem splitAll_field (key value t : List Nat) (h : space ∉ key ++ equals :: value) :
    splitAll (key ++ equals :: (value ++ space :: t)) = (key ++ equals :: value) :: splitAll t := by
  have shape : key ++ equals :: (value ++ space :: t) = (key ++ equals :: value) ++ space :: t := by
    simp
  rw [shape, splitAll_append_space _ _ h]

/-- The fields of a marker that release-glz renders split back into one field per key. -/
theorem split_fields (values : Values) (spaceless : Spaceless values) :
    splitSpaces (fields values) =
      [packageKey ++ equals :: values.package, branchKey ++ equals :: values.branch,
        headKey ++ equals :: values.head, digestKey ++ equals :: values.digest,
        versionKey ++ equals :: values.version, intentKey ++ equals :: values.intent] := by
  obtain ⟨package', branch', head', digest', version', intent'⟩ := spaceless
  have free : ∀ key value : List Nat, key ∈ [packageKey, branchKey, headKey, digestKey,
      versionKey, intentKey] → space ∉ value → space ∉ key ++ equals :: value := by
    intro key value member valueFree
    simp only [List.mem_append, List.mem_cons, not_or]
    refine ⟨?_, by decide, valueFree⟩
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl <;> decide
  unfold splitSpaces fields segment
  simp only [List.append_assoc, List.cons_append]
  rw [splitAll_field _ _ _ (free _ _ (by decide) package'),
    splitAll_field _ _ _ (free _ _ (by decide) branch'),
    splitAll_field _ _ _ (free _ _ (by decide) head'),
    splitAll_field _ _ _ (free _ _ (by decide) digest'),
    splitAll_field _ _ _ (free _ _ (by decide) version'),
    splitAll_of_not_mem _ (free _ _ (by decide) intent')]
  simp [packageKey, branchKey, headKey, digestKey, versionKey, intentKey]

/-- The fields of a marker that release-glz renders give back every value. -/
theorem the_fields_give_back_every_value (values : Values) (spaceless : Spaceless values) :
    markerValues (splitSpaces (fields values)) = some values := by
  rw [split_fields values spaceless]
  have keyFree : ∀ key, key ∈ [packageKey, branchKey, headKey, digestKey, versionKey,
      intentKey] → equals ∉ key := by decide
  simp only [markerValues, recordAll,
    splitField_key packageKey _ (keyFree _ (by decide)),
    splitField_key branchKey _ (keyFree _ (by decide)),
    splitField_key headKey _ (keyFree _ (by decide)),
    splitField_key digestKey _ (keyFree _ (by decide)),
    splitField_key versionKey _ (keyFree _ (by decide)),
    splitField_key intentKey _ (keyFree _ (by decide))]
  simp [slotOf, packageKey, branchKey, headKey, digestKey, versionKey, intentKey]

/-- A Release PR body of inert text and a rendered marker carries exactly that marker: it ends the body after the text, and its fields give back every value. -/
theorem the_marker_round_trips (text : List Nat) (values : Values) (spaceless : Spaceless values) :
    markerStart (inert text ++ render values) = some (inert text).length ∧
      markerValues (splitSpaces (fields values)) = some values :=
  ⟨a_rendered_marker_ends_the_body _ values (inert_holds_no_less_than text) spaceless,
    the_fields_give_back_every_value values spaceless⟩

#print axioms inert_holds_no_less_than
#print axioms a_rendered_marker_ends_the_body
#print axioms an_earlier_marker_is_refused
#print axioms the_fields_give_back_every_value
#print axioms the_marker_round_trips

end ReleaseGlz.Marker
