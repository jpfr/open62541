from libc.stdint cimport uint8_t, uint16_t, int32_t, uint32_t, uint16_t, int64_t
from libcpp cimport bool as bool_t

# Disable some GCC warnings inherent to the Cython generated code
cdef extern from *:
    """
#pragma GCC diagnostic ignored "-Wpedantic"
    """

# Define the builtin types and DataType structure
cdef extern from "open62541/types.h":
    ctypedef uint32_t UA_StatusCode;

    ctypedef union _NodeIdIdentifier:
        uint32_t numeric

    ctypedef struct UA_String:
        size_t length
        uint8_t *data

    ctypedef int64_t UA_DateTime

    ctypedef struct Guid:
        uint32_t data1;
        uint16_t data2;
        uint16_t data3;
        uint8_t data4[8]

    ctypedef UA_String UA_ByteString
    ctypedef UA_String UA_XMLElement

    ctypedef struct UA_NodeId:
        uint16_t namespaceIndex
        int32_t identifierType
        _NodeIdIdentifier identifier

    ctypedef struct UA_ExpandedNodeId:
        UA_NodeId nodeId
        UA_String namespaceUri
        uint32_t serverIndex

    ctypedef struct UA_QualifiedName:
        uint16_t namespaceIndex
        UA_String name

    ctypedef struct UA_LocalizedText:
        UA_String locale
        UA_String text

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

    ctypedef struct UA_Variant:
        const UA_DataType *type
        int32_t storageType
        size_t arrayLength
        void *data
        size_t arrayDimensionsSize
        uint32_t *arrayDimensions

    ctypedef struct UA_ExtensionObject:
        int32_t encoding
        # TODO

    ctypedef struct UA_DataValue:
        UA_Variant value
        UA_DateTime sourceTimestamp
        UA_DateTime serverTimestamp
        uint16_t sourcePicoseconds
        uint16_t serverPicoseconds
        UA_StatusCode status
        bool_t hasValue
        bool_t hasStatus
        bool_t hasSourceTimestamp
        bool_t hasServerTimestamp
        bool_t hasSourcePicoseconds
        bool_t hasServerPicoseconds

    ctypedef struct UA_DiagnosticInfo:
        bool_t hasSymbolicId
        bool_t hasNamespaceUri
        bool_t hasLocalizedText
        bool_t hasLocale
        bool_t hasAdditionalInfo
        bool_t hasInnerStatusCode
        bool_t hasInnerDiagnosticInfo
        int32_t symbolicId
        int32_t namespaceUri
        int32_t localizedText
        int32_t locale
        UA_String additionalInfo
        UA_StatusCode innerStatusCode
        UA_DiagnosticInfo *innerDiagnosticInfo

cdef class Server:
    cdef bool_t running

    def run(self, int port=4840):
        self.running = True
        return 0

    def stop(self):
        self.running = False
