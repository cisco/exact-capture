The Exact Capture software system comprises 4 major internal components:

1. One or more “hot” threads - to read packets from the ExaNIC(s) into memory
2. One or more “cold” threads - to write packets from memory to disk(s)
3. One or more shared memory queues - to connect the hot and cold threads to each other
4. One management thread - responsible for control and statistics collection / reporting

These basic architectural components are illustrated below, with the addition of the ExaNIC and ExaDisk resources.
The head of each column highlights the performance limiting resource for that component:

![Exact Capture Architecture](img/exact-capture-arch.png)

_This page was last updated on ._                              
