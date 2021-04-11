event zeek_init()
	{
	local r1=SumStats::Reducer($stream="http.lookup",$apply=set(SumStats::SUM,SumStats::UNIQUE));
        local r2=SumStats::Reducer($stream="http",$apply=set(SumStats::SUM));
	SumStats::create([$name="http.404.found",$epoch=10mins,$reducers=set(r2,r1),
	                  $epoch_result(ts:time,key:SumStats::Key,result:SumStats::Result)=
	                  {local r_404=result["http.lookup"];
                           local r_all=result["http"];
	                  if(r_404$num>2)
	                  if(r_404$num/r_all$num>0.2)
	                  if(r_404$unique/r_404$num>0.5){
	                  print fmt("%s is a scanner with %d scan attemps on %d urls",key$host,r_404$num,r_404$unique);
	                  }}]);
	
	}

event http_reply(c:connection,version:string,code:count,reason:string)
	{
	SumStats::observe("http", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
	if(code==404)
	{
	SumStats::observe("http.lookup",[$host=c$id$orig_h],[$str=c$http$uri]);
	}
	}
