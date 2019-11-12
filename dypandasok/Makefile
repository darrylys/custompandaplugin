# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
CFLAGS+=-std=c++11
LIBS+=-lcapstone

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o \
	$(PLUGIN_OBJ_DIR)/AnalysisEngine.o \
	$(PLUGIN_OBJ_DIR)/pp_range.o \
	$(PLUGIN_OBJ_DIR)/proc_util.o \
	$(PLUGIN_OBJ_DIR)/Tracer.o \
	$(PLUGIN_OBJ_DIR)/api_filter.o 
