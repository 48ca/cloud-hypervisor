// Copyright 2026 Google LLC
//
// SPDX-License-Identifier: Apache-2.0

fn main() {
    prost_build::Config::new()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute("MemoryDescriptor", "#[serde(default)]")
        .type_attribute("NumaNode", "#[serde(default)]")
        .type_attribute("VfioDevice", "#[serde(default)]")
        .type_attribute("VmOptions", "#[serde(default)]")
        .compile_protos(
            &["src/proto/state.proto", "src/proto/config.proto"],
            &["src/proto/"],
        )
        .unwrap();
}
