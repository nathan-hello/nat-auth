package natauth

import (
	"github.com/nathan-hello/nat-auth/db"
	"github.com/nathan-hello/nat-auth/lib"
)

func New(c lib.Config, d db.Accessor) {
	lib.InitConfig(c)
	lib.InitDb(d)
}
