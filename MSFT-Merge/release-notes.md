### Release Version: {{rolling lts tag}}
 
### LTS Base Version: {{LTS Tag}}
 
### Release Date: {{Date}}
 
# Overview
 
This release, based on the Long-Term Support (LTS) version {{LTS Tag}}, introduces several key updates and improvements specific to our internal requirements. The custom tag {{rolling lts tag}} highlights the primary focus and enhancements in this release.

## OpenHCL memory usage

Disable block-layer data integrity support in the x64 and ARM64 HCL
configurations, including CVM-x64 builds that inherit the x64 configuration.
OpenHCL's storage paths do not use Linux block-integrity metadata. This
avoids the unused integrity buffer pool introduced upstream, which reserves
4 MiB at boot and can cause VTL2 out-of-memory failures with the 70 MiB
release memory layout. The VTL2 memory budget is unchanged.
