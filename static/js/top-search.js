(function(){
  var input=document.getElementById('topSearchInput'),box=document.getElementById('topSearchResults');
  if(!input||!box)return;
  var timer=null,seq=0;
  function esc(s){var d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML;}
  function render(res,q){
    var groups=[['Students',res.students],['Staff',res.staff],['Classes',res.classes],['Features',res.features]],html='',n=0;
    groups.forEach(function(g){if(g[1]&&g[1].length){html+='<div class="tsr-group">'+g[0]+'</div>';g[1].forEach(function(i){n++;html+='<a class="tsr-item" href="'+esc(i.url)+'"><b>'+esc(i.name||i.label)+'</b>'+(i.sub?'<small>'+esc(i.sub)+'</small>':'')+'</a>';});}});
    if(!n)html='<div class="tsr-empty">No results found for “'+esc(q)+'”.</div>';
    else html+='<a class="tsr-all" href="/search?q='+encodeURIComponent(q)+'">See all results</a>';
    box.innerHTML=html;box.hidden=false;
  }
  input.addEventListener('input',function(){
    var q=input.value.trim();clearTimeout(timer);
    if(q.length<2){box.hidden=true;return;}
    timer=setTimeout(function(){
      var my=++seq;
      fetch('/api/search?q='+encodeURIComponent(q),{credentials:'same-origin',headers:{'Accept':'application/json'}})
        .then(function(r){if(!r.ok)throw new Error(r.status);return r.json();})
        .then(function(res){if(my===seq)render(res,q);})
        .catch(function(){box.innerHTML='<div class="tsr-empty">Search is unavailable right now. Check your connection and try again.</div>';box.hidden=false;});
    },220);
  });
  document.addEventListener('click',function(e){if(!box.contains(e.target)&&e.target!==input)box.hidden=true;});
  input.addEventListener('keydown',function(e){if(e.key==='Escape'){box.hidden=true;}});
})();
