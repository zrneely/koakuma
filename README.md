# Koakuma

Koakuma is a Windows-only command line tool designed to help you find large files and folders on your NTFS-formatted drives.

Because it reads the NTFS Master File Table, Koakuma must be run elevated (with the `SE_BACKUP_NAME` and `SE_RESTORE_NAME` privileges).

## Features

* Koakuma is aware of sparse files and OneDrive's Files on Demand, and will not count them towards disk usage (unlike WizTree).
* No animated "donate" button (unlike WizTree).
* Koakuma is aware of alternate data streams, and will count all data streams towards a file's total size. It can also count only non-default data streams to help you identify files with large ADSs.
* You can filter the analysis by extension (whitelist or blacklist).
* By default, Koakuma includes hidden files and excludes system files.

## Command Line Arguments

```
> koakuma.exe -h
koakuma 0.1.0
Zachary Neely <zrussellneely@gmail.com>
Finds big files and folders

USAGE:
    koakuma.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help               Prints help information
    -i, --include_system     Include files marked 'system' in the analysis
    -d, --only_alt_data      Include only non-default $DATA streams in the analysis
    -s, --skip_hidden        Exclude files marked 'hidden' from the analysis
    -p, --skip_priv_check    Skip the privilege check usually performed when the app starts
    -V, --version            Prints version information

OPTIONS:
    -b, --extension_blacklist <extension_blacklist>
            A comma-separated ist of extensions (do not include dots) to exclude from the analysis

    -w, --extension_whitelist <extension_whitelist>
            A comma-separated list of extensions (do not include dots) to include in the analysis

    -n, --max_count <max_count>                        The maximum number of results to display
```

## Example Output

```
> koakuma.exe
Reading C:\...
████████████████████████████████████████████████████████████████████████████████████████████████████████ 434176/434176
Read 434176 MFT entries in 8 seconds (49496 entries/sec)
Largest files on C: by allocated size:
        52759 C:\Recovery\Customizations\ICB.ppkg: 2.09GiB
        81976 C:\Windows\SoftwareDistribution\Download\75b55ce526640b7b2d7d7b3d1bb1d62e\Windows10.0-KB4524570-x64.cab: 312.75MiB
        2902 C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb: 280.00MiB
        261862 C:\Windows\System32\MRT.exe: 123.25MiB
        147769 C:\Program Files\Mozilla Firefox\xul.dll: 102.27MiB

Largest directories on C: by total allocated size of immediate children:
        C:\Recovery\Customizations: 4.18GiB
        C:\Windows\System32: 2.05GiB
        C:\Users\zrneely\AppData\Local\Mozilla\Firefox\Profiles\q8y2tdt9.default-release\cache2\entries: 2.01GiB
        C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_65e19dc65ea77797: 1.48GiB
        C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache: 1.17GiB

Largest extensions on C: by total allocated size:
        dll (total size: 10.20GiB)
        ppkg (total size: 2.10GiB)
        exe (total size: 1.92GiB)
        lib (total size: 1.57GiB)
        dat (total size: 1.07GiB)
```