/* -*-mode:c++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 sw=2 tw=80 : */

#ifndef GRAPH_HH
#define GRAPH_HH

#include <iosfwd>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "thunk/thunk.hh"
#include "util/optional.hh"

typedef std::string Hash;

// # Introductio
//
// This data structure manages the (concurrent) reduction of LISP-like terms.
//
// At its core it is a DAG of `Computation`s, which are keyed by unique
// `ComputationId`s.
//
// A computation can be:
//   * A `Value`: a primitive term, that need not be further reduced
//   * A `Thunk`: a non-primitive term
//   * A `LINK`: a copy of some other `Thunk`.
//      * This can be viewed as an "indentity" thunk.
//
// It helps to start by ignoring thunks.
//
// Critical operations:
//
//   * `add_thunk(Thunk) -> set<Hash>`: thi
//
//

enum class ComputationKind {
  VALUE,    // This node has been evalutated
  THUNK,    // This node is unevaluated
  LINK      // This node is unevaluated and is a copy of another
};

std::ostream& operator<<(std::ostream&, const ComputationKind&);

// A computation denotes a node in the graph which is in the process of being reduced.
// If (+ 3 4) was reduced to 7, then both would have the same ComputationId,
// just at different points in time.
typedef size_t ComputationId;
struct Computation {
  Computation(const Computation& other) = default;
  Computation & operator=(const Computation& other) = default;
  // Whether the `thunk` field accurately reflects the current state
  bool up_to_date {false};
  // The executable (but potentially out-of-date) thunk
  gg::thunk::Thunk thunk;

  // If we detemine that this computation is equivalent to another one, then
  // this field is set to true, and the deps will be that node.
  bool is_link_{false};

  // The outputs for this computation. Empty if a thunk. Non-empty if a value.
  std::vector<gg::ThunkOutput> outputs {};

  // Computations that this one depends on.
  std::unordered_set<ComputationId> deps {};
  // Computations dependent on this one.
  std::unordered_set<ComputationId> rev_deps {};
  // The hashes that this thunk knows its dependencies by
  std::unordered_map<ComputationId, Hash> dep_hashes {};

  Computation( gg::thunk::Thunk && thunk );

  ComputationKind kind() const;
  bool is_value() const { return outputs.size(); }
  bool is_link() const { return outputs.empty() and is_link_; }
  bool is_thunk() const { return outputs.empty() and not is_link_; }

  // Return whether a reduction from `hash` is applicable to this node.
  bool is_reducible_from_hash( const std::string& hash ) const;
};

using HashSet = std::unordered_set<Hash>;
using IdSet = std::unordered_set<ComputationId>;

class ExecutionGraph
{
private:
  // Computations, maybe irreducible, maybe not
  std::unordered_map<ComputationId, Computation> computations_ {};

  bool verbose;

  // Number of computations that are now values
  size_t n_values {0};

  // The ComputationId for known hashes
  std::unordered_map<Hash, ComputationId> ids_ {};

  // The hashes of pre-existing blobs (values or executables) that this
  // function depends on.
  HashSet blob_dependencies_ {};

  ComputationId next_id_ {0};

  bool log_renames_;

  // Place the thunk at the indicated location, and pull in dependencies
  // Returns any new order one dependencies.
  HashSet _emplace_thunk( ComputationId id,
                                           gg::thunk::Thunk && thunk );

  // Given a computation `id`, ensures that said `id` either:
  //    * refers to a value OR
  //    * refers to a link to a thunk OR
  //    * refers to an up-to-date thunk (that has its hash in the hash index)
  // Returns any newly-executable thunks.
  IdSet _update( const ComputationId id );

  // Given a computation `id`, updates all parents (and parents of links)
  // and returns all ids that have been updated to be executable.
  IdSet _update_parent_thunks( const ComputationId id );

  // Given a computation `id`, marks this `id` (and all transitive dependents)
  // as out-of-date.
  void _mark_out_of_date( const ComputationId id );

  // Record that `from` depends on `on`. `on_hash` is the **parent's** name for
  // the child.
  void _create_dependency( const ComputationId from,
                           const Hash & on_hash,
                           const ComputationId on );

  // Remove the dependency from `from` on `on`.
  // Returns the hashes of any removed nodes
  std::vector<Hash>
  _erase_dependency( const ComputationId from,
                          const ComputationId on );

  // Cut the dependencies from `computation`
  // Returns the hashes of any removed nodes
  std::vector<Hash>
  _cut_dependencies( const ComputationId id );

  // Removes this node if it has no dependents. Recursive.
  // Returns the hashes of any removed nodes
  std::vector<Hash>
  _remove_if_unneeded( const ComputationId id );

  // Given `id`, follow link pointer until a computation that does not have any
  // links.
  ComputationId _follow_links( const ComputationId id ) const;

  std::pair<ComputationId, HashSet> _add_inner_thunk( const Hash & hash );
  // Adds a computation for this thunk to the graph. A No-op if present.
  // Returns the id of the added thunk, and the hash of any new order-one
  // dependencies.
  std::pair<ComputationId, HashSet> _add_thunk_common( const Hash & hash );

public:
  // If `log_renames` is set, then the graph will record changes in thunk
  // hashes.
  ExecutionGraph(const bool log_renames);
  ExecutionGraph(const ExecutionGraph& other) = delete;
  ExecutionGraph & operator=(const ExecutionGraph& other) = delete;

  // Adds a computation for this thunk to the graph.
  // Returns 
  HashSet add_thunk( const Hash & hash );

  // Given a `hash`, determines the value of that hash, if it is known.
  Optional<Hash> query_value( const Hash & hash ) const;

  // Informs that graph that `from` reduces to `to`.
  // Returns a pair of newly executable thunks, and no-longer needed thunks.
  std::pair<HashSet, std::vector<Hash>>
  submit_reduction( const Hash& from, std::vector<gg::ThunkOutput>&& to );

  // Get initial blobs that the computation is dependent on
  const HashSet & blob_dependencies() const { return blob_dependencies_; }

  size_t size() const { return computations_.size() - n_values; }
};

#endif /* GRAPH_HH */
