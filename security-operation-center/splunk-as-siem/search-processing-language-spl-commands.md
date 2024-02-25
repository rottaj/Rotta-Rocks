# Search Processing Language (SPL) Commands



## Basic Commands

By default a search query returns all results, but can be narrowed down with keywords, boolean operators, wildcards, and more.

### fields

The `fields` command specifies which fields should be included or excluded in the search results.&#x20;

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | fields - User
```

### table

The `table` command presents search results in a tabular format.&#x20;

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image
```

### rename

The `rename` command renames a field in the search results.&#x20;

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rename Image as Process
```

### dedup

The `dedup` command removes duplicates.

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | dedup Image
```

### Sort

The `sort` command sorts the search results. (example sorts results in decending order)

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | sort - _time
```

### stats

The `stats` command performs statistical operations. (example returns a table of timestamp (`_time`) and a process (`Image`)"

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | stats count by _time, Image
```

### chart

The `chart` command creates a data visualization based on statistical operations.

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | chart count by _time, Image
```

### eval

The `eval` command creates or redefines fields. (example creates a new field `Process_Path` which contains the lowercase version of the `Image` field)

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval Process_Path=lower(Image)
```

### rex

The `rex` command extracts new fields from existing ones using regular expressions.

```splunk-spl
index="main" EventCode=4662 | rex max_match=0 "[^%](?<guid>{.*})" | table guid
```

* `index="main" EventCode=4662` filters the events to those in the `main` index with the `EventCode` equal to `4662`. This narrows down the search to specific events with the specified EventCode.
* `rex max_match=0 "[^%](?<guid>{.*})"` uses the rex command to extract values matching the pattern from the events' fields. The regex pattern `{.*}` looks for substrings that begin with `{` and end with `}`. The `[^%]` part ensures that the match does not begin with a `%` character. The captured value within the curly braces is assigned to the named capture group `guid`.
* `table guid` displays the extracted GUIDs in the output. This command is used to format the results and display only the `guid` field.
* The `max_match=0` option ensures that all occurrences of the pattern are extracted from each event. By default, the rex command only extracts the first occurrence.

### lookup

The `lookup` command enriches the data with external sources

Suppose the following CSV file called `malware_lookup.csv`.

```splunk-spl
filename, is_malware
notepad.exe, false
cmd.exe, false
powershell.exe, false
sharphound.exe, true
randomfile.exe, true
```

### inputlookup

The `inputlookup` command retrieves data from a lookup file without joining it to the search results.

```splunk-spl
| inputlookup malware_lookup.csv
```

### Time Range

Every event in Splunk has a timestamp. We can limit the searches to specific time periods using the `earliest` and `latest` commands.

```splunk-spl
index="main" earliest=-7d EventCode!=1
```

### transaction

The transaction command is used in Splunk to group events that share common characteristics into transcation.

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3) | transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m | table Image |  dedup Image 
```

### subsearches

A subsearch in Splunk is a search that is nested inside another search.

```splunk-spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 NOT [ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | top limit=100 Image | fields Image ] | table _time, Image, CommandLine, User, ComputerName
```



## Identify Available Data

Splunk can ingest a wide variety of data sources. To identify available source types we can run the followning SPL commands:

#### Using fields command:

We can get Account\_Name, EventCode and create a table of the summarized data.

```splunk-spl
sourcetype="WinEventLog:Security" | fields Account_Name, EventCode | table Account_Name, EventCode
```

#### View list of fields

If we can to get a list of fields we can use the command:

```splunk-spl
sourcetype="WinEventLog:Security" | fieldsummary
```



This command displays the 20 least common values of the `ParentImage` field.

```splunk-spl
index="main" | rare limit=20 useother=f ParentImage
```

\
A more complex query can provide a detailed summary of fields. This search shows a summary of all fields (`fieldsummary`), filters out fields that appear in less than 100 events (`where count < 100`)

```splunk-spl
index=* sourcetype=* | fieldsummary | where count < 100 | table field, count, distinct_count
```



Good command:

```splunk-spl
index=* sourcetype=* | bucket _time span=1d | stats count by _time, index, sourcetype | sort - _time
```

\
A more complex query can provide a detailed summary of fields.

```splunk-spl
index=* | sistats count by index, sourcetype, source, host
```

### Additional Commands

```splunk-spl
| eventcount summarize=false index=* | table index
```

This query uses `eventcount` to count events in all indexes, then `summarize=false` is used to display counts for each index separately, and finally, the `table` command is used to present the data in tabular form.

```splunk-spl
| metadata type=sourcetypes
```

The result is a list of all `sourcetypes` in our Splunk environment, along with additional metadata such as the first time a source type was seen (`firstTime`), the last time it was seen (`lastTime`), and the number of hosts (`totalCount`).

Simpler view:

```splunk-spl
| metadata type=sourcetypes index=* | table sourcetype
```

Here, the `metadata` command retrieves metadata about the data in our indexes.\
In table form:

```splunk-spl
| metadata type=sources index=* | table source
```



**Once we know our source types, we can investigate the kind of data they contain.**

Say we're interesting in: <mark style="color:yellow;">WinEventLog:Security</mark>

```splunk-spl
sourcetype="WinEventLog:Security" | table _raw
```

The `table` command generates a table with the specified fields as columns. Here, `_raw` represents the raw event data. This command will return the raw data for the specified source type.

