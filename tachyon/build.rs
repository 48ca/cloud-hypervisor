// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

fn main() {
    prost_build::compile_protos(&["src/proto/state.proto"], &["src/proto/"]).unwrap();
}
