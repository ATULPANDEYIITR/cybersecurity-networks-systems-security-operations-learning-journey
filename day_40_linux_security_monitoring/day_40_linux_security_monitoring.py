# Practice: Python Data Structures

## Purpose

This practical module studies how collections represent, organize, retrieve, and process data. It progresses from built-in containers to custom data structures and algorithms, using inventory management, operational events, work queues, employee training, and delivery routing as realistic examples.

The implementations have different purposes:

- **Python** develops a broad working understanding of built-in containers and custom structures.
- **JavaScript** focuses on array transformations, `Map`, `Set`, event ingestion, and bounded queues.
- **C++** models inventory replenishment and weighted delivery routes using standard-library containers.
- **Java** models employee training records through immutable domain types, nested maps, state counts, and validation.
- **PostgreSQL** represents persistent operational collections through relational tables, constraints, indexes, transactions, and recursive queries.

The programs are independent. Each can be executed without requiring the other implementations.

## Fundamental collection choices

A data structure is useful when its organization matches the operations an application performs. A collection that is convenient for insertion may be unsuitable for repeated searches, ordered processing, or relationships between entities.

| Structure | Organization | Typical operation | Typical complexity |
|---|---|---|---|
| List or dynamic array | Ordered sequence | Index access | O(1) |
| Dynamic array | Contiguous indexed elements | Append | O(1) amortized |
| Tuple | Fixed sequence of references | Index access | O(1) |
| Dictionary or hash map | Keys associated with values | Key lookup | O(1) average |
| Set | Unique hashable elements | Membership test | O(1) average |
| Deque | Elements accessible at both ends | Append or remove at either end | O(1) |
| Heap | Partially ordered elements | Read minimum or maximum | O(1) for the root |
| Heap | Partially ordered elements | Insert or remove root | O(log n) |
| Singly linked list | Nodes connected by references | Search by value | O(n) |
| Binary search tree | Keys arranged by comparison | Search | O(log n) average for a balanced tree; O(n) worst case |
| Graph | Vertices connected by edges | Traverse reachable vertices | O(V + E) with adjacency lists |

Here, \(n\) is the number of elements, \(V\) is the number of vertices, and \(E\) is the number of edges. Complexity depends on implementation details, key-distribution assumptions, and whether a tree remains balanced.

## Lists, tuples, and dictionaries

### Lists

Lists are suitable when order matters and the collection must change over time. The Python implementation demonstrates appending, insertion, removal, slicing, comprehensions, filtering, and sorting.

A list slice creates a new outer list, but it does not recursively copy nested objects. Assigning a list to another variable creates an alias, so mutations through either reference affect the same object.

Sorting also requires care. Python's `sorted()` returns a new list, whereas `list.sort()` changes the existing list. Sorting with a meaningful key, such as a normalized product name, makes the intended ordering explicit.

### Tuples

Tuples represent ordered groups of references, such as an employee identifier, role, and location. They are immutable containers, but this does not make every object reachable through a tuple immutable. A tuple containing a list can still expose changes to that list.

A tuple is hashable only when its contents are hashable. Consequently, a tuple containing a list cannot be used as a dictionary key or set member.

### Dictionaries

Dictionaries associate unique keys with values. The Python inventory example uses SKU strings as keys and nested dictionaries for quantity and reorder thresholds.

The `get()` method supports optional lookups without raising `KeyError`. `setdefault()` is useful when a collection must be initialized before appending. `defaultdict` simplifies repeated aggregation, and dictionary comprehensions create derived mappings without manually constructing each entry.

Dictionary keys must be hashable. Average lookup performance is typically constant time, although pathological collision behavior and expensive hashing can affect performance.

## Sets and frequency analysis

A set stores unique hashable elements. It is appropriate for membership checks, duplicate detection, and operations involving overlapping collections.

Union combines the distinct elements of two sets. Intersection returns common elements. Difference identifies elements present in one collection but not the other, while symmetric difference returns elements that occur in exactly one collection.

The Python program uses sets to compare request identifiers. Its `Counter` example instead counts repeated events. These structures solve different problems: a set discards duplicate occurrences, whereas a frequency counter preserves their counts.

The JavaScript implementation adds an important language-specific distinction. JavaScript `Set` compares objects by identity rather than by their property values. Two separately created objects with identical properties are still distinct set members.

## Stacks, queues, and priority processing

### Stack

A stack follows last-in, first-out ordering. The Python `Stack` class uses list append and pop operations, making it suitable for undo histories, nested processing, and backtracking. Both removal and inspection explicitly reject an empty stack.

### Queue

A queue follows first-in, first-out ordering. Python's `deque` supports efficient removal from the left, unlike repeatedly removing the first element from an ordinary list.

The JavaScript implementation uses an array with a moving head index. It avoids shifting all remaining elements after each dequeue and periodically compacts consumed entries. Its capacity limit provides a simple form of backpressure: new events are rejected when the queue is full.

### Priority queue

A priority queue retrieves work according to priority rather than arrival order. Python's `heapq` implements a min-heap, so smaller numeric priority values are removed first.

The C++ replenishment scheduler reverses the comparator to make lower urgency numbers appear first in `std::priority_queue`. Ties are resolved by SKU, providing deterministic ordering for tasks with the same urgency.

A heap does not maintain a fully sorted array. It maintains enough ordering to expose the root efficiently. Insertion and removal take O(log n), while reading the root takes O(1).

## Linked lists and trees

### Singly linked lists

The Python `SinglyLinkedList` stores nodes containing values and references to subsequent nodes. A tail reference makes append operations O(1). Searching and deleting a value require traversal and therefore take O(n).

Deletion must update the head when removing the first node and the tail when removing the final node. The implementation also handles deletion from an empty list and deletion of a missing value.

Linked lists do not automatically outperform arrays. They incur per-node memory overhead and do not provide constant-time indexing.

### Binary search trees

The binary search tree stores smaller keys in the left subtree and larger keys in the right subtree. In-order traversal returns unique inserted keys in sorted order.

The implementation ignores duplicate keys. It demonstrates the search and insertion rules but does not rebalance the tree. If keys arrive in sorted order, the tree can become a chain, causing search and insertion to degrade to O(n). Production workloads with unpredictable input often benefit from self-balancing trees.

### Hierarchical data in PostgreSQL

The SQL implementation represents categories through a self-referencing foreign key. A recursive common table expression traverses the parent-child relationships and calculates the depth of each category.

The foreign key prevents references to nonexistent parent categories. The self-reference check prevents a category from directly referencing itself. More elaborate applications must also prevent longer cycles, which may require additional validation or controlled update procedures.

## Graphs and route planning

Graphs model relationships that cannot be adequately represented by a simple hierarchy. A vertex represents a location, and an edge represents a possible route. Weighted edges carry distance or cost.

The Python and C++ programs use adjacency maps. Each vertex maps to its neighboring vertices and the corresponding route weights.

Both implementations use Dijkstra's algorithm to find a minimum-cost route. A priority queue selects the currently cheapest discovered vertex. When a shorter route is found, the algorithm records the new distance and predecessor. Stale queue entries are skipped, and predecessors are followed backward to reconstruct the route.

The algorithms require non-negative edge weights. Both implementations reject negative route costs rather than silently applying an algorithm outside its valid assumptions.

With adjacency lists and a binary heap, Dijkstra's algorithm typically runs in O((V + E) log V) time. The sample graph is small, but the approach scales more effectively than enumerating every possible route.

The PostgreSQL example stores directed route records. It uses recursive path expansion and an array of visited facilities to avoid revisiting vertices in the same path. That query is a small-network demonstration, not a replacement for a specialized shortest-path engine on large graphs. Enumerating simple paths can grow exponentially.

## Implementation details by language

### Python implementation

The Python file demonstrates built-in containers before implementing stacks, queues, linked lists, trees, and a weighted graph.

Its inventory dictionaries model SKU-indexed records, while sets and `Counter` handle uniqueness and frequency analysis. The linked-list implementation maintains both head and tail references, and the graph uses a heap-backed shortest-path algorithm.

The data-validation function checks required dictionary fields, rejects Boolean values where numeric hours are expected, normalizes strings, and enforces a maximum number of hours. These checks illustrate why a structurally valid dictionary is not necessarily a valid business record.

The deep-copy example shows how nested mutable objects can be shared unintentionally. The final assertions exercise important behavior, including stack order, linked-list deletion, route reconstruction, and negative-weight rejection.

### JavaScript implementation

The JavaScript file emphasizes collection transformations and operational event handling.

Arrays support `filter()`, `map()`, and `reduce()` for selecting paid orders, producing summaries, and calculating totals. The implementation copies an array before sorting because `sort()` mutates its receiver.

`Map` provides explicit key-value storage, while `Set` supports membership checks and stable deduplication. A frequency index normalizes event names before counting them.

The bounded `EventQueue` uses a head index and periodically compacts the backing array. Its capacity check prevents unbounded growth in this in-memory example. The asynchronous section uses `Promise.all()` to combine successful batches and `Promise.allSettled()` to retain both successful and failed outcomes.

These mechanisms are useful in event-processing systems where batches arrive asynchronously and processing order, duplicate handling, and failure reporting must be explicit.

### C++ case study

The C++ program models a distribution centre that tracks stock, schedules replenishment, and plans deliveries.

`Inventory` uses `std::unordered_map` for average constant-time SKU lookup. It rejects duplicate identifiers, invalid quantities, and non-finite or negative unit costs. Reorder candidates are copied into a vector and sorted so that output does not depend on unordered-map iteration order.

`ReplenishmentScheduler` combines `std::priority_queue` with `std::unordered_set`. The heap determines processing order, while the set prevents a SKU from receiving duplicate active tasks. Removing a task also removes its SKU from the active set, allowing that item to be scheduled again later.

`RouteGraph` uses nested ordered maps to represent weighted adjacency lists. Its Dijkstra implementation tracks tentative distances and predecessor vertices. Missing destinations return an infinite distance and an empty path.

The example demonstrates a practical trade-off: unordered containers offer efficient average-case lookup, while ordered containers offer predictable iteration order. Assertions verify that duplicate SKUs, missing records, and negative route distances are handled correctly.

### Java implementation

The Java program models employee training compliance in an enterprise environment.

The `Employee`, `Course`, and `Enrollment` records make the domain data explicit. Compact record constructors validate required strings, allowed hours, scores, and completed-course conditions.

`TrainingRegistry` stores employees and courses in maps keyed by identifiers. Nested enrollment maps provide direct access to a specific employee-course combination. Re-enrolling an employee updates the existing state and adjusts the status counts instead of creating a duplicate enrollment.

An `EnumMap` provides type-safe aggregation by `CourseStatus`. Sets identify employees who have completed mandatory courses, and streams sort completed enrollment records and calculate department-level statistics.

The registry distinguishes an unknown employee from a missing enrollment and rejects completion records that exceed course requirements or lack a passing score. These domain-level checks prevent invalid state from entering the in-memory registry.

### PostgreSQL implementation

The SQL file represents durable operational collections in the `data_structures_practice` schema.

- `inventory_items` uses a primary key to provide SKU-based identity. Check constraints enforce non-negative quantities, reorder levels, and costs.
- `inventory_movements` references inventory items and stores changes as an ordered event history. A composite index supports retrieval by SKU and descending event time.
- `operational_events` assigns unique event keys and stores variable attributes in `JSONB`, combining relational identity with flexible event payloads.
- `work_items` stores task state and priority. A partial index accelerates selection of pending tasks.
- `categories` represents a hierarchy through a self-referencing foreign key.
- `routes` stores weighted facility connections and uses a composite primary key to prevent duplicate directed edges.
- `employee_skill_tags` enforces uniqueness for each employee and skill combination.

The pending-work query uses `FOR UPDATE SKIP LOCKED` so concurrent workers can claim different records without waiting on rows already locked by other workers. This provides a database-backed queue pattern, although a complete production queue also needs retry policies, leases, and failure recovery.

The transaction groups the demonstration data and operations into a single commit boundary. A failed statement in the transaction must be handled according to PostgreSQL transaction rules before the transaction can commit.

## Correctness and common failure modes

### Mutation and aliasing

A copied outer container may still share nested lists, dictionaries, or objects. The Python example uses `deepcopy()` when independent nested state is required. Deep copying is not universally appropriate, particularly for resources such as open files, network connections, or objects that intentionally share identity.

### Duplicate handling

Duplicates must be defined by the application's identity rule. A set of strings naturally deduplicates identical strings. A set of JavaScript objects deduplicates identical references, not objects with matching properties. Database primary keys and unique constraints enforce identity rules durably across concurrent transactions.

### Missing values

A missing dictionary key, an absent JavaScript `Map` entry, an unknown C++ SKU, and a missing SQL row have different failure mechanisms. Code should choose whether to return an optional value, raise an exception, or reject the operation. Silent defaults can conceal invalid identifiers when absence is not an expected condition.

### Ordering assumptions

Ordinary sets do not represent a sorted collection. Dictionary insertion order in modern Python and insertion order in JavaScript `Map` are useful properties, but they do not imply priority ordering. A heap, sorted sequence, or database `ORDER BY` clause is needed when processing order is part of the requirement.

### Validation and consistency

Input validation should happen before state mutation. The examples check identifier formats, quantities, priorities, route weights, scores, and state requirements. PostgreSQL constraints add another layer of protection when multiple application processes access the same records.

Application validation and database constraints are complementary. Application code can return understandable errors, while database constraints protect stored data from invalid writes made through other code paths.

## Performance and practical selection

Choose structures based on the operations that dominate the workload.

- Use a list when sequence order and indexing matter.
- Use a dictionary or `Map` for frequent key-based retrieval.
- Use a set for membership checks and uniqueness.
- Use a deque for repeated insertion and removal at both ends.
- Use a heap when the next item must be selected by priority.
- Use a linked list when node-level insertion or deletion is useful and node references are already available.
- Use a tree when ordered lookup or hierarchical organization is required.
- Use a graph when entities have general many-to-many relationships or weighted paths.
- Use relational tables when records need durable identity, referential integrity, concurrent updates, and queryable relationships.

For larger workloads, measure actual time and memory usage instead of relying solely on asymptotic complexity. Hash-based structures depend on suitable hashing, heaps require explicit tie-breaking when deterministic ordering matters, and recursive algorithms may encounter call-stack limits. Persistent systems also need to consider transaction isolation, index maintenance, concurrency, and recovery after failures.
