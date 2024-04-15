package leveldb

import (
	"testing"

	"github.com/omegasuite/goleveldb/leveldb/testutil"
)

func TestLevelDB(t *testing.T) {
	testutil.RunSuite(t, "LevelDB Suite")
}
