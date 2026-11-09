// The Group filter is a primary/global filter rendered statically in the
// topbar (see dashboard.html), not among the regular toolbar filters, but it
// still participates in getFilters()/recordMatchesFilters()/optionValues()
// like every other filter because those functions operate generically on
// every element carrying a `data-filter` attribute, wherever it lives in the DOM.
const GROUP_FILTER_FIELD={key:'group',label:'Group',field:'Group'};
const FILTER_FIELDS=[
  {key:'app_space_owner',label:'AppSpace Owner',field:'AppSpaceOwner'},
  {key:'app_space_name',label:'AppSpace',field:'AppSpaceName'},
  {key:'environment',label:'Environment',field:'Environment'},
  {key:'severity',label:'Severity',field:'Severity'},
  {key:'status',label:'Status',field:'Status'},
  {key:'remit_team',label:'Remit Team',field:'RemitTeam'},
  {key:'app_space_team',label:'Team',field:'AppSpaceTeam'},
  {key:'operating_system',label:'Operating System',field:'Operating System'},
  {key:'type_category',label:'Category',field:'Type Category'},
  {key:'pci_required',label:'PCI Required',value:record=>record['PCI Required']?'Yes':'No'},
  {key:'sla_breach',label:'SLA Breach',value:record=>record.SLABreach?'Yes':'No'},
  {key:'new_resolved_status',label:'New / Resolved Status',field:'NewResolvedStatus'},
  {key:'exploit',label:'Exploit',value:record=>(record.Exploit===true||String(record.Exploit).toUpperCase()==='TRUE')?'TRUE':'FALSE',showInToolbar:false},
  {key:'fundamental_classification',label:'Fundamental Classification',field:'FundamentalClassification',showInToolbar:false},
  {key:'zone',label:'Zone',field:'Zone',showInToolbar:false},
  {key:'resolution',label:'Resolution',value:record=>(record['Resolution Date']||['Resolved','Closed'].includes(record.Status))?'Resolved':'Unresolved',showInToolbar:false},
];
function escapeHtml(value){return String(value).replace(/[&<>'"]/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));}
function filterDefinition(key){if(key===GROUP_FILTER_FIELD.key)return GROUP_FILTER_FIELD;return FILTER_FIELDS.find(definition=>definition.key===key);}
function recordFilterValue(record,key){const definition=filterDefinition(key);if(!definition)return'';const value=definition.value?definition.value(record):record[definition.field];return value===undefined||value===null?'':String(value);}
function selectedValues(select){return select.multiple?[...select.selectedOptions].map(option=>option.value).filter(Boolean):(select.value?[select.value]:[]);}
function getFilters(){return Object.fromEntries([...document.querySelectorAll('[data-filter]')].map(el=>[el.dataset.filter,selectedValues(el)]));}
function recordMatchesFilters(record,filters,ignoreKey){return Object.entries(filters).every(([key,values])=>key===ignoreKey||!values.length||values.includes(recordFilterValue(record,key)));}
function optionValues(records,key){return [...new Set(records.map(record=>recordFilterValue(record,key)).filter(Boolean))].sort((a,b)=>a.localeCompare(b,undefined,{numeric:true,sensitivity:'base'}));}
function setSelectOptions(select,values){const current=selectedValues(select);select.innerHTML='<option value="">All</option>'+values.map(value=>`<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('');current.filter(value=>values.includes(value)).forEach(value=>{const option=[...select.options].find(item=>item.value===value);if(option)option.selected=true;});}
function updateFilterOptions(data){let changed=false;const filters=getFilters();document.querySelectorAll('[data-filter]').forEach(select=>{const key=select.dataset.filter;const available=optionValues((data.records||[]).filter(record=>recordMatchesFilters(record,filters,key)),key);const before=selectedValues(select).join('\u001f');setSelectOptions(select,available);const after=selectedValues(select).join('\u001f');if(before!==after)changed=true;select.disabled=!available.length;});return changed;}
function buildFilters(data,onChange){const host=document.getElementById('filters');host.innerHTML='';FILTER_FIELDS.filter(definition=>definition.showInToolbar!==false).forEach(definition=>{const labelElement=document.createElement('label');labelElement.className='filter-control';labelElement.innerHTML=`<span>${definition.label}</span>`;const select=document.createElement('select');select.dataset.filter=definition.key;select.setAttribute('aria-label',definition.label);select.addEventListener('change',()=>{updateFilterOptions(data);onChange();});labelElement.appendChild(select);host.appendChild(labelElement);});const groupSelect=document.querySelector(`[data-filter="${GROUP_FILTER_FIELD.key}"]`);if(groupSelect)groupSelect.addEventListener('change',()=>{updateFilterOptions(data);onChange();});updateFilterOptions(data);}
function resetFilters(data){document.querySelectorAll('[data-filter]').forEach(el=>{[...el.options].forEach(option=>{option.selected=false;});el.value='';});updateFilterOptions(data);}
function activeFilterSummary(){return Object.entries(getFilters()).filter(([,values])=>values.length).map(([key,values])=>({label:(filterDefinition(key)||{}).label||key,values}));}
