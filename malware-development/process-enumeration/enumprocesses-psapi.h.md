---
description: >-
  EnumProcesses returns a list of process ID's. We can then use OpenProcess to
  obtain a handle on the processes for further enumeration.
---

# EnumProcesses (psapi.h)

EnumProcesses is a quick and easy way to get all process ID's on a Windows system. **It's a good idea to use a large array because it's hard to predict how many processes there will be at the time you call EnumProcesses.**

<pre class="language-c"><code class="lang-c">#include &#x3C;windows.h>
#include &#x3C;stdio.h>
#include &#x3C;tchar.h>
#include &#x3C;psapi.h>
<strong>
</strong><strong>int main( void )
</strong>{
    // Get the list of process identifiers.

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &#x26;cbNeeded ) )
    {
        return 1;
    }


    // Calculate how many process identifiers were returned.

    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.

    for ( i = 0; i &#x3C; cProcesses; i++ )
    {
        if( aProcesses[i] != 0 )
        {
            // calls OpenProcess to get handle
            PrintProcessNameAndID( aProcesses[i] );
        }
    }

    return 0;
}
</code></pre>

