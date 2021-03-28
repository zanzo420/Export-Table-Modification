# Export Table Modification
Export Table Modification or ETM, can be used to hook exported functions from other modules or even your own module.

## How does this work? 🤔
This project works by iterating through the export table until the function we want to hook is found, then we swap the address of the exported function in the table.

## How detectable is this? 🕵️
In my opinion, it is hard to detect until we compare the module loaded in memory with the module in disk, because we aren't allocating memory but finding an codecave inside the module which we then overwrite the bytes, if the anti cheat traces where the export lands, then it will appear in the same module.

## Bugs or issues 🐛
* Known Issues/Bugs
  * GetProcAddress doesn't return the same address of our codecave (won't be fixed, because certain functions are cached).

If you find any bugs or issues, feel free to report the issue or make a pull request to make the code better 😄
