# open62541 Realtime Publisher

This example is a self-contained PubSub publisher over raw Ethernet to
showcase the realtime-capabilities of OPC UA PubSub even if the publisher is
configured from a full OPC UA server and takes the data for publication from the
information model.

The core idea is that the publisher callback can be triggered from a system
interrupt and sends out the PubSub message within the interrupt. The specific
techniques used to make the OPC UA server reentrant (to enable publisher
interrupts in the same thread as the "normal" OPC UA server) are described in
this publication:

```
@inproceedings{pfrommer2018open,
  title={Open source OPC UA PubSub over TSN for realtime industrial communication},
  author={Pfrommer, Julius and Ebner, Andreas and Ravikumar, Siddharth and Karunakaran, Bhagath},
  booktitle={2018 IEEE 23rd International Conference on Emerging Technologies and Factory Automation (ETFA)},
  pages={1087--1090},
  year={2018},
  organization={IEEE}
}
```

Please cite if you use this work.

## Building the RT Publisher

The main open62541 library needs to be built with these build options enabled
for the realtime PubSub example. Note that some of the examples supplied with
open62541 will not link against the library with these build options.

- UA_ENABLE_PUBSUB
- UA_ENABLE_PUBSUB_ETH_UADP
- UA_ENABLE_PUBSUB_CUSTOM_PUBLISH_HANDLING
- UA_ENABLE_MALLOC_SINGLETON
- UA_ENABLE_IMMUTABLE_NODES

The publisher contains some hard-coded values that need to be adjusted to
specific systems. Please check the top definitions in
`pubsub_interrupt_publish.c` and `start_rt_publish.sh`.

The RT publisher code can be built and linked against the main open62541 library as follows:

`gcc ../examples/pubsub_realtime/pubsub_interrupt_publish.c ../examples/pubsub_realtime/bufmalloc.c -I../include -I../plugins/include -Isrc_generated -I../arch/posix -I../arch -I../plugins/networking bin/libopen62541.a -lrt -o rt_publisher`

## Running the RT Publisher

The publisher must be run as root for direct access to the Ethernet interface.
The following command starts the publisher, locks the process to a specific CPU,
and sets the scheduling policy.

`# start_rt_publish.sh ./rt_publisher`

The measurements are written to a file (publisher_measurement.csv) with the
following fields for every publish callback:

- Counter
- Publication Interval
- Nominal time for the current publish
- Start delay from the nominal time
- Duration of the publish callback
