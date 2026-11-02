/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Loads the Site CA from its files and issues leaf certificates with it.
//! This module doesn't handle HTTP.
//!
//! No route serves a certificate revocation list, so the CA doesn't sign one.

mod certificate_authority;
#[cfg(test)]
pub(crate) mod test_support;

pub(crate) use certificate_authority::{
    CaFiles, CertificateAuthority, IssueError, IssuedCertificate, LoadError,
};
