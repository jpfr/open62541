from libc.stdint cimport uint8_t, uint16_t, int32_t, uint32_t, uint16_t
from libcpp cimport bool as bool_t

cdef extern from "open62541/types.h":
    ctypedef bool_t UA_Boolean;
    ctypedef uint32_t UA_StatusCode;

    ctypedef union _NodeIdIdentifier:
        uint32_t numeric

    ctypedef struct UA_NodeId:
        uint16_t namespaceIndex
        int32_t identifierType
        _NodeIdIdentifier identifier

    ctypedef struct UA_DataTypeMember:
        const char *memberName
        const UA_DataType *memberType
        uint8_t padding
        uint8_t isArray
        uint8_t isOptional

    ctypedef struct UA_DataType:
        const char *typeName
        UA_NodeId typeId
        UA_NodeId binaryEncodingId
        uint32_t memSize
        uint32_t typeKind
        uint32_t pointerFree
        uint32_t overlayable
        uint32_t membersSize
        UA_DataTypeMember *members

cdef class Server:
    cdef bool_t running

    def run(self, int port=4840):
        self.running = True
        return 0

    def stop(self):
        self.running = False
