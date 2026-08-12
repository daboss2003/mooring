package edge
import ("strings";"testing")
func TestAccessLogRender(t *testing.T){
	base:=baseCfg(); base.AccessLog=true
	out,err:=Render(base,nil,nil); if err!=nil{t.Fatal(err)}
	s:=string(out)
	for _,want:=range []string{`"logging"`,`"default_logger_name": "mooring_access"`,`"http.log.access.mooring_access"`,`"output": "stdout"`,`"output": "stderr"`,`"format": "json"`}{
		if !strings.Contains(s,want){t.Errorf("access-log render missing %q",want)}
	}
	// OFF by default: no logging block when AccessLog is false.
	base2:=baseCfg(); out2,_:=Render(base2,nil,nil)
	if strings.Contains(string(out2),`"logging"`){t.Error("access logging must be OFF unless requested")}
}
