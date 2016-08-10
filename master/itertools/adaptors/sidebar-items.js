initSidebarItems({"struct":[["Batching","A “meta iterator adaptor”. Its closure recives a reference to the iterator and may pick off as many elements as it likes, to produce the next iterator element."],["Coalesce","An iterator adaptor that may join together adjacent elements."],["Combinations","An iterator to iterate through all the combinations of pairs in a `Clone`-able iterator."],["CombinationsN","An iterator to iterate through all the `n`-length combinations in an iterator."],["Dedup","An iterator adaptor that removes repeated duplicates."],["Flatten","An iterator adapter to simply flatten a structure."],["GroupBy","An iterator adaptor that groups iterator elements. Consecutive elements that map to the same key (“runs”), are returned as the iterator elements."],["Interleave","An iterator adaptor that alternates elements from two iterators until both run out."],["InterleaveShortest","An iterator adaptor that alternates elements from the two iterators until one of them runs out."],["MendSlices","An iterator adaptor that glues together adjacent contiguous slices."],["Merge","An iterator adaptor that merges the two base iterators in ascending order. If both base iterators are sorted (ascending), the result is sorted."],["MergeBy","An iterator adaptor that merges the two base iterators in ascending order. If both base iterators are sorted (ascending), the result is sorted."],["MultiPeek","An iterator adaptor that allows the user to peek at multiple `.next()` values without advancing itself."],["Product","An iterator adaptor that iterates over the cartesian product of the element sets of two iterators `I` and `J`."],["PutBack","An iterator adaptor that allows putting back a single item to the front of the iterator."],["PutBackN","An iterator adaptor that allows putting multiple items in front of the iterator."],["Step","An iterator adaptor that steps a number elements in the base iterator for each iteration."],["TakeWhileRef","An iterator adaptor that borrows from a `Clone`-able iterator to only pick off elements while the predicate returns `true`."],["Unique","An iterator adapter to filter out duplicate elements."],["UniqueBy","An iterator adapter to filter out duplicate elements."],["WhileSome","An iterator adaptor that filters `Option<A>` iterator elements and produces `A`. Stops on the first `None` encountered."]]});