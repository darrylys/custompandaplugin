# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# NDEBUG to remove asserts in wintrospection
CFLAGS+=-D_DEBUG
# LIBS+=

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o \
	$(PLUGIN_OBJ_DIR)/dywin7x86sp1apilogger.o \
    $(PLUGIN_OBJ_DIR)/StructMetaData.o \
    $(PLUGIN_OBJ_DIR)/LiteralMetaData.o \
    $(PLUGIN_OBJ_DIR)/ZeroTerminatedStringData.o \
    $(PLUGIN_OBJ_DIR)/LengthSpecifiedStringData.o \
    $(PLUGIN_OBJ_DIR)/StructData.o \
    $(PLUGIN_OBJ_DIR)/WinTypes.o \
    $(PLUGIN_OBJ_DIR)/LiteralData.o \
    $(PLUGIN_OBJ_DIR)/CommonData.o \
    $(PLUGIN_OBJ_DIR)/CommonMetaData.o \
    $(PLUGIN_OBJ_DIR)/StringMetaData.o \
    $(PLUGIN_OBJ_DIR)/CsvReader.o \
    $(PLUGIN_OBJ_DIR)/ISerializer.o \
    $(PLUGIN_OBJ_DIR)/JsonSerializer.o \
    $(PLUGIN_OBJ_DIR)/WinTypeData2JsonSerializer.o \
    $(PLUGIN_OBJ_DIR)/utils.o \
    $(PLUGIN_OBJ_DIR)/WinApis.o \
    $(PLUGIN_OBJ_DIR)/apilogger.o \
    $(PLUGIN_OBJ_DIR)/winhelper.o \
    $(PLUGIN_OBJ_DIR)/win7x86trospection.o \
    
