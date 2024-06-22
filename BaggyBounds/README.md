# Baggy Bounds
Ported an earlier open source implementaiton of baggy bounds

## Changes 
1. Bug fixes and changes related to 64 bit, function arguments whose bounds need to be saved.</item>
2. Precise mode flag enabled - to only save bounds data for unsafe stack objects specified

## Pending/ Not currently supported
1. GEPs with vector indices 
2. Std Libraries  - Ideally use LLVM sanitizer like approach i.e. could integrate into LLVM's compiler-rt library
3. Original VR analysis not integrated
    

### Referencesq
1. [Baggy Bounds Open Source Implementation](https://github.com/jynnantonix/baggy-bounds)


