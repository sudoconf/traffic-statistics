CC = gcc
object = traffic-st-tool.c

traffic-st-tool: $(object)
	@$(CC) -o $@ $^
	@echo "CC $@"

.PHONY : clean
clean:
	@rm -rf traffic-st-tool
	@rm -rf *.o
	@echo "RM *.o traffic-st-tool"
