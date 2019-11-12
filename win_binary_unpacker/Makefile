# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/config.o \
	$(PLUGIN_OBJ_DIR)/entropy_heur.o \
	$(PLUGIN_OBJ_DIR)/environment.o \
	$(PLUGIN_OBJ_DIR)/heur_util.o \
	$(PLUGIN_OBJ_DIR)/logger.o \
	$(PLUGIN_OBJ_DIR)/longjmpheur.o \
	$(PLUGIN_OBJ_DIR)/osi_process.o \
	$(PLUGIN_OBJ_DIR)/pe_module.o \
	$(PLUGIN_OBJ_DIR)/proc_info.o \
	$(PLUGIN_OBJ_DIR)/unpacker_main.o \
	$(PLUGIN_OBJ_DIR)/Win32ProcDumper.o \
	$(PLUGIN_OBJ_DIR)/Win32ProcParser.o \
	$(PLUGIN_OBJ_DIR)/winhelper.o \
	
