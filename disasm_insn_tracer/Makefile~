# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
LIBS+=-lcapstone

# I DON'T KNOW WHY, but the LAST '\' MUST EXIST OTHERWISE THE PLUGIN .so FILE IS NOT GENERATED!
# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/main.o \
	$(PLUGIN_OBJ_DIR)/osi_process.o \
	$(PLUGIN_OBJ_DIR)/winhelper.o \
	$(PLUGIN_OBJ_DIR)/utility.o \
	$(PLUGIN_OBJ_DIR)/pandawinpeheader.o \
	$(PLUGIN_OBJ_DIR)/winpehdr.o \
	
