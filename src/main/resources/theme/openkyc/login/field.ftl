<#macro group name label error="">
  <div class="${properties.kcFormGroupClass!}">
    <label for="${name}" class="${properties.kcLabelClass!}">${label}</label>
    <#nested>
    <#if error?has_content>
      <span class="${properties.kcInputErrorMessageClass!}">${error}</span>
    </#if>
  </div>
</#macro>
