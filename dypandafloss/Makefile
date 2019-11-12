# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
LIBS+=-lcapstone

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o \
	$(PLUGIN_OBJ_DIR)/ArithmeticFilter.o \
	$(PLUGIN_OBJ_DIR)/MovFilter.o \
	$(PLUGIN_OBJ_DIR)/ShiftFilter.o \
	$(PLUGIN_OBJ_DIR)/XorFilter.o
