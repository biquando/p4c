/*
Copyright 2019 Orange

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _UBPF_MODEL_P4_
#define _UBPF_MODEL_P4_

#include <core.p4>

#ifndef UBPF_MODEL_VERSION
#define UBPF_MODEL_VERSION 20200515
#endif

const bit<32> __ubpf_model_version = UBPF_MODEL_VERSION;

#if UBPF_MODEL_VERSION >= 20200515
enum ubpf_action {
    ABORT,
    DROP,
    PASS,
    REDIRECT
}

// struct standard_metadata {
//     bit<32>     input_port;
//     bit<32>     packet_length;
//     ubpf_action output_action;
//     bit<32>     output_port;
//     bool        clone;
//     bit<32>     clone_port;
// }
struct standard_metadata {
    bit<9>      ingress_port;
    bit<9>      egress_spec;
    bit<9>      egress_port;
    bit<32>     instance_type;
    bit<32>     packet_length;
    //
    // @alias is used to generate the field_alias section of the BMV2 JSON.
    // Field alias creates a mapping from the metadata name in P4 program to
    // the behavioral model's internal metadata name. Here we use it to
    // expose all metadata supported by simple switch to the user through
    // standard_metadata_t.
    //
    // flattening fields that exist in bmv2-ss
    // queueing metadata
    @alias("queueing_metadata.enq_timestamp")
    bit<32> enq_timestamp;
    @alias("queueing_metadata.enq_qdepth")
    bit<19> enq_qdepth;
    @alias("queueing_metadata.deq_timedelta")
    bit<32> deq_timedelta;
    /// queue depth at the packet dequeue time.
    @alias("queueing_metadata.deq_qdepth")
    bit<19> deq_qdepth;

    // intrinsic metadata
    @alias("intrinsic_metadata.ingress_global_timestamp")
    bit<48> ingress_global_timestamp;
    @alias("intrinsic_metadata.egress_global_timestamp")
    bit<48> egress_global_timestamp;
    /// multicast group id (key for the mcast replication table)
    @alias("intrinsic_metadata.mcast_grp")
    bit<16> mcast_grp;
    /// Replication ID for multicast
    @alias("intrinsic_metadata.egress_rid")
    bit<16> egress_rid;
    /// Indicates that a verify_checksum() method has failed.
    /// 1 if a checksum error was found, otherwise 0.
    bit<1>  checksum_error;
    /// Error produced by parsing
    // error parser_error;
    /// set packet priority
    @alias("intrinsic_metadata.priority")
    bit<3> priority;
}
#endif

/*
 * The uBPF target can currently pass the packet or drop it.
 * By default, all packets are passed.
 * The mark_to_drop() extern can be used to mark a packet to be dropped.
 * The mark_to_drop() modifies only the state hidden from the user's P4 program.
 * mark_to_drop() should be called only in the 'pipe' control.
 */
extern void mark_to_drop();

/*
 * The uBPF target can currently pass the packet or drop it.
 * By default, all packets are passed.
 * The mark_to_pass() extern can be used to mark a packet to be passed (it cancels previous mark_to_drop() action).
 * The mark_to_pass() modifies only the state hidden from the user's P4 program.
 * mark_to_pass() should be called only in the 'pipe' control.
 */
extern void mark_to_pass();


extern Register<T, S> {
  /***
   * A Register object is created by calling its constructor.
   * You must provide a size of Register. The size specifies
   * the maximum number of entries stored by Register.
   * After constructing the Register object, you can use it in
   * both actions or apply blocks.
   * The Register is not intialized when created.
   */
  Register(bit<32> size);

  /***
   * read() reads the state (T) of the register array stored at the
   * specified index S, and returns it as the value written to the
   * result parameter.
   *
   * @param index The index of the register array element to be
   *              read, normally a value in the range [0, size-1].
   * @return Returns result  of type T. Only types T that are bit<W>
   *         are currently supported.  When index is in range, the value of
   *         result becomes the value read from the register
   *         array element.  When index >= size, the final
   *         value of result is not specified, and should be
   *         ignored by the caller.
   */
  T read  (in S index);


  void write (in S index, in T value);
}

/*
 * The extern used to get the current timestamp in nanoseconds.
 */
extern bit<48> ubpf_time_get_ns();

/***
 * Truncate packet to the maximum size
 *
 * @param len   Maximum length of the packet (from beginning of packet) in
 *              bytes, further bytes will be removed. If deparsed packet is
 *              shorter than len, this extern has no effect.
 *              Minimum value for len is 14, as a packet in Open vSwitch must
 *              have at least Ethernet header. Smaller values than 14 will be
 *              adjusted to the minimum value by switch.
 */
extern void truncate(in bit<32> len);

enum HashAlgorithm {
    lookup3
}

/***
 * Calculate a hash function of the value specified by the data
 * parameter. Due to the limitation of uBPF back-end the maximum width of data is bit<64>.
 *
 * Note that the types of all of the parameters may be the same as, or
 * different from, each other, and thus their bit widths are allowed
 * to be different.
 *
 * Note that the result will have always the bit<32> width.
 *
 * @param D    Must be a tuple type where all the fields are bit-fields (type bit<W> or int<W>) or varbits.
 *             Maximum width of D is 64 bit (limitation of uBPF back-end).
 */
extern void hash<D>(out bit<32> result, in HashAlgorithm algo, in D data);

/***
 * Compute the checksum via Incremental Update (RFC 1624).
 * This function implements checksum computation for 16-bit wide fields.
 */
extern bit<16> csum_replace2(in bit<16> csum,  // current csum
                             in bit<16> old,   // old value of the field
                             in bit<16> new);

/***
 * Compute the checksum via Incremental Update (RFC 1624).
 * This function implements checksum computation for 32-bit wide fields.
 */
extern bit<16> csum_replace4(in bit<16> csum,
                             in bit<32> old,
                             in bit<32> new);

/*
 * Architecture.
 *
 * M must be a struct.
 *
 * H must be a struct where every one of its members is of type
 * header, header stack, or header_union.
 */

#if UBPF_MODEL_VERSION >= 20200515
parser parse<H, M>(packet_in packet, out H headers, inout M meta, inout standard_metadata std);
#else
parser parse<H, M>(packet_in packet, out H headers, inout M meta);
#endif

#if UBPF_MODEL_VERSION >= 20200515
control pipeline<H, M>(inout H headers, inout M meta, inout standard_metadata std);
#else
control pipeline<H, M>(inout H headers, inout M meta);
#endif

/*
 * The only legal statements in the body of the deparser control are:
 * calls to the packet_out.emit() method.
 */
@deparser
control deparser<H>(packet_out b, in H headers);

package ubpf<H, M>(parse<H, M> prs,
                pipeline<H, M> ingress,
                pipeline<H, M> egress,
                deparser<H> dprs);

#endif /* _UBPF_MODEL_P4_ */
