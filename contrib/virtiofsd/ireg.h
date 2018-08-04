#define VERSION_TABLE_MAGIC 0x7265566465726853

enum ireg_op {
	IREG_GET,
	IREG_PUT,
};

struct ireg_msg {
	enum ireg_op op;
	uint64_t handle;
	union {
		struct {
			uint64_t ino;
			uint64_t dev;
		} get;
		struct {
			uint64_t refid;
		} put;
	};
};

enum srv_op {
	SRV_VERSION,
};

struct srv_msg {
	enum srv_op op;
	uint64_t handle;
	struct {
		uint64_t refid;
		uint64_t offset;
	} version;
};

