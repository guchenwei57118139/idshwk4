global num_all:count=0;
event zeek_init()
	{
	local r1=SumStats::Reducer($stream="http.lookup",$apply=set(SumStats::UNIQUE));
	SumStats::create([$name="http.404.found",$epoch=10mins,$reducers=set(r1),
	                  $epoch_result(ts:time,key:SumStats::Key,result:SumStats::Result)=
	                  {local r=result["http.lookup"];
	                  if(r$num>2)
	                  if(r$num/num_all>0.2)
	                  if(r$unique/r$num>0.5){
	                  print fmt("%s is a scanner with %d scan attempts on %d urls.",key$host,r$num,r$unique);
	                  }}]);
	
	}

event http_reply(c:connection,version:string,code:count,reason:string)
	{
	++num_all;
	if(code==404)
	{
	SumStats::observe("http.lookup",[$host=c$id$orig_h],[$str=c$http$uri]);
	}
	}
