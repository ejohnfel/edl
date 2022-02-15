PYTHONLIB = /usr/lib/python3.9
OLDPYTHONLIB = /usr/lib/python3.8

BINHOME = /usr/local/bin

TARGET = edl.py
BINTARGET = edl

oldinstall: $(TARGET)
	@cp $(TARGET) $(OLDPYTHONLIB)

install: $(TARGET) oldinstall
	@[ -e $(BINHOME)/$(BINTARGET) ] && rm $(BINHOME)/$(BINTARGET) || return 0
	@cp $(TARGET) $(PYTHONLIB)
	@ln -s $(PYTHONLIB)/$(TARGET) $(BINHOME)/$(BINTARGET)
	@chmod +x $(BINHOME)/$(BINTARGET)
