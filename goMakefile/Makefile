GOOS := windows
GOARCH := amd64
GARBLE := garble
# 这里是源文件
MAIN_GO := main.go

# 定义不同的 garble 参数组合
GARBLE_CONFIGS := no_obfs literals tiny literals_tiny

# 定义不同的 ldflags 参数组合
LDFLAGS_CONFIGS := none sw sw_gui full static_only gui_only

# 定义 ldflags 的具体值
LDFLAGS_none := 
LDFLAGS_sw := -ldflags="-s -w"
LDFLAGS_sw_gui := -ldflags="-s -w -H=windowsgui"
LDFLAGS_full := -ldflags="-s -w -H=windowsgui -extldflags=-static"
LDFLAGS_static_only := -ldflags="-extldflags=-static"
LDFLAGS_gui_only := -ldflags="-H=windowsgui"

# 生成所有配置组合
TARGETS := $(foreach g,$(GARBLE_CONFIGS),$(foreach l,$(LDFLAGS_CONFIGS),run_$(g)_$(l).exe))

all: $(TARGETS)

.PHONY: all clean

# 构建规则
run_no_obfs_%.exe: $(MAIN_GO)
	@echo "Building no_obfs with $* ldflags..."
	go build $(LDFLAGS_$*) -o $@ $(MAIN_GO)

run_literals_%.exe: $(MAIN_GO)
	@echo "Building literals with $* ldflags..."
	$(GARBLE) -literals -seed=random build $(LDFLAGS_$*) -o $@ $(MAIN_GO)

run_tiny_%.exe: $(MAIN_GO)
	@echo "Building tiny with $* ldflags..."
	$(GARBLE) -tiny -seed=random build $(LDFLAGS_$*) -o $@ $(MAIN_GO)

run_literals_tiny_%.exe: $(MAIN_GO)
	@echo "Building literals_tiny with $* ldflags..."
	$(GARBLE) -literals -tiny -seed=random build $(LDFLAGS_$*) -o $@ $(MAIN_GO)

clean:
	@echo "Cleaning..."
	rm -f $(TARGETS)