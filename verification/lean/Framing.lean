set_option autoImplicit false

namespace ReleaseGlz.Framing

/-- The eight big-endian bytes of `n`, which the core writes as the length of a part. -/
def be8 (n : Nat) : List Nat :=
  [n / 2 ^ 56 % 256, n / 2 ^ 48 % 256, n / 2 ^ 40 % 256, n / 2 ^ 32 % 256,
    n / 2 ^ 24 % 256, n / 2 ^ 16 % 256, n / 2 ^ 8 % 256, n % 256]

/-- The number that eight big-endian bytes stand for. -/
def fromBe8 : List Nat → Nat
  | [b0, b1, b2, b3, b4, b5, b6, b7] =>
    ((((((b0 * 256 + b1) * 256 + b2) * 256 + b3) * 256 + b4) * 256 + b5) * 256 + b6) * 256 + b7
  | _ => 0

theorem be8_length (n : Nat) : (be8 n).length = 8 := rfl

theorem fromBe8_be8 (n : Nat) (bound : n < 2 ^ 64) : fromBe8 (be8 n) = n := by
  simp only [be8, fromBe8]
  omega

theorem be8_injective (a b : Nat) (bound_a : a < 2 ^ 64) (bound_b : b < 2 ^ 64)
    (same : be8 a = be8 b) : a = b := by
  rw [← fromBe8_be8 a bound_a, ← fromBe8_be8 b bound_b, same]

/-- The framing of one file: the length of its path, the path, the length of its contents, and the contents. -/
def frameFile (path contents : List Nat) : List Nat :=
  be8 path.length ++ path ++ be8 contents.length ++ contents

/-- The bytes the files digest hashes: the domain tag and then every file's framing in order. -/
def frameFiles (domain : List Nat) (files : List (List Nat × List Nat)) : List Nat :=
  domain ++ (files.map fun file => frameFile file.1 file.2).flatten

/-- A file whose path and contents each have fewer than 2^64 bytes, as every file on a real machine does. -/
def Representable (file : List Nat × List Nat) : Prop :=
  file.1.length < 2 ^ 64 ∧ file.2.length < 2 ^ 64

theorem frameFile_prefix (path₁ contents₁ path₂ contents₂ rest₁ rest₂ : List Nat)
    (first : Representable (path₁, contents₁)) (second : Representable (path₂, contents₂))
    (same : frameFile path₁ contents₁ ++ rest₁ = frameFile path₂ contents₂ ++ rest₂) :
    path₁ = path₂ ∧ contents₁ = contents₂ ∧ rest₁ = rest₂ := by
  unfold frameFile at same
  simp only [List.append_assoc] at same
  obtain ⟨path_lengths, same⟩ := List.append_inj same (by simp [be8_length])
  have path_length : path₁.length = path₂.length :=
    be8_injective _ _ first.1 second.1 path_lengths
  obtain ⟨paths, same⟩ := List.append_inj same path_length
  obtain ⟨contents_lengths, same⟩ := List.append_inj same (by simp [be8_length])
  have contents_length : contents₁.length = contents₂.length :=
    be8_injective _ _ first.2 second.2 contents_lengths
  obtain ⟨contents, rests⟩ := List.append_inj same contents_length
  exact ⟨paths, contents, rests⟩

theorem frameFile_length (path contents : List Nat) :
    16 ≤ (frameFile path contents).length := by
  simp [frameFile, be8_length]
  omega

/-- Two lists of representable files that frame into the same bytes are the same list, for lists and files of every length. -/
theorem the_files_framing_is_injective (domain : List Nat)
    (first second : List (List Nat × List Nat))
    (first_fits : ∀ file ∈ first, Representable file) (second_fits : ∀ file ∈ second, Representable file)
    (same : frameFiles domain first = frameFiles domain second) : first = second := by
  unfold frameFiles at same
  have frames := List.append_cancel_left same
  clear same
  induction first generalizing second with
  | nil =>
    cases second with
    | nil => rfl
    | cons file rest =>
      have lengths := congrArg List.length frames
      simp only [List.map_nil, List.flatten_nil, List.length_nil, List.map_cons,
        List.flatten_cons, List.length_append] at lengths
      have := frameFile_length file.1 file.2
      omega
  | cons file rest ih =>
    cases second with
    | nil =>
      have lengths := congrArg List.length frames
      simp only [List.map_nil, List.flatten_nil, List.length_nil, List.map_cons,
        List.flatten_cons, List.length_append] at lengths
      have := frameFile_length file.1 file.2
      omega
    | cons other others =>
      simp only [List.map_cons, List.flatten_cons] at frames
      obtain ⟨paths, contents, rests⟩ :=
        frameFile_prefix file.1 file.2 other.1 other.2 _ _
          (first_fits file (List.mem_cons_self ..)) (second_fits other (List.mem_cons_self ..)) frames
      have heads : file = other := Prod.ext paths contents
      rw [heads, ih others (fun f m => first_fits f (List.mem_cons_of_mem _ m))
        (fun f m => second_fits f (List.mem_cons_of_mem _ m)) rests]

/-- The bytes the idempotency key of a notification hashes: the domain tag, the Candidate digest, a NUL byte, and the hook id. -/
def frameNotification (domain digest hook : List Nat) : List Nat :=
  domain ++ digest ++ [0] ++ hook

theorem separated (digest₁ digest₂ hook₁ hook₂ : List Nat)
    (clean₁ : 0 ∉ digest₁) (clean₂ : 0 ∉ digest₂)
    (same : digest₁ ++ 0 :: hook₁ = digest₂ ++ 0 :: hook₂) : digest₁ = digest₂ ∧ hook₁ = hook₂ := by
  induction digest₁ generalizing digest₂ with
  | nil =>
    cases digest₂ with
    | nil => simpa using same
    | cons byte rest =>
      simp at same
      exact absurd (same.1 ▸ List.mem_cons_self ..) clean₂
  | cons byte rest ih =>
    cases digest₂ with
    | nil =>
      simp at same
      exact absurd (same.1 ▸ List.mem_cons_self ..) clean₁
    | cons other others =>
      simp only [List.cons_append, List.cons.injEq] at same
      obtain ⟨heads, tails⟩ := same
      obtain ⟨digests, hooks⟩ :=
        ih others (fun m => clean₁ (List.mem_cons_of_mem _ m))
          (fun m => clean₂ (List.mem_cons_of_mem _ m)) tails
      exact ⟨by rw [heads, digests], hooks⟩

/-- Two notifications whose Candidate digests hold no NUL byte and that frame into the same bytes have the same digest and hook, for every length. -/
theorem the_notification_framing_is_injective (domain digest₁ digest₂ hook₁ hook₂ : List Nat)
    (clean₁ : 0 ∉ digest₁) (clean₂ : 0 ∉ digest₂)
    (same : frameNotification domain digest₁ hook₁ = frameNotification domain digest₂ hook₂) :
    digest₁ = digest₂ ∧ hook₁ = hook₂ := by
  unfold frameNotification at same
  simp only [List.append_assoc, List.singleton_append] at same
  exact separated digest₁ digest₂ hook₁ hook₂ clean₁ clean₂ (List.append_cancel_left same)

#print axioms fromBe8_be8
#print axioms the_files_framing_is_injective
#print axioms the_notification_framing_is_injective

end ReleaseGlz.Framing
