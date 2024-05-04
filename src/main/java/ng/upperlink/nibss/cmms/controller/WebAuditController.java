package ng.upperlink.nibss.cmms.controller;

import ng.upperlink.nibss.cmms.api.WebAuditSearch;
import ng.upperlink.nibss.cmms.dto.WebAppAuditEntryDto;
import ng.upperlink.nibss.cmms.service.WebAppAuditEntryService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/webaudit")
@Slf4j
public class WebAuditController {

    private WebAppAuditEntryService auditEntryService;


    public WebAuditController(final WebAppAuditEntryService auditEntryService) {

        this.auditEntryService = auditEntryService;
    }

    @GetMapping
    public Page<WebAppAuditEntryDto> fetchAuditTrail(WebAuditSearch search) {

        Pageable pageable = new PageRequest(search.getDataPageNo(), search.getDataSize());

        Page<WebAppAuditEntryDto> page = null;

        if(search.isDateEmpty()) {
            if(search.isAllEmpty()) {

                page = auditEntryService.findAllStrippedDown(pageable);

            }  else if(search.isOnlyUsername()) {
                page = auditEntryService.findByUser(search.getUsername(), pageable);

            } else if( search.isOnlyClassName()) {
                page = auditEntryService.findByClassName(search.getClassName(), pageable);
            } else if(search.isUsernameAndClassName()) {
                page = auditEntryService.findByUserAndClassName(search.getUsername(),
                        search.getClassName(), pageable);
            }
        } else {

            if(search.isAllEmpty()) {
                page = auditEntryService.findByDateRange(search.getFrom(), search.getTo(),pageable);
            } else if( search.isUsernameAndClassName()) {

                page = auditEntryService.findByUserAndClassNameAndDateRange(
                        search.getUsername(), search.getClassName(),
                        search.getFrom(), search.getTo(), pageable);

            } else if(search.isOnlyUsername()) {
                page = auditEntryService.findByUserAndDateRange(search.getUsername(), search.getFrom(),
                        search.getTo(),pageable);

            } else if( search.isOnlyClassName()) {

                page = auditEntryService.findByClassNameAndDateRange(search.getClassName(),
                        search.getFrom(), search.getTo(), pageable);
            }
        }

        return page;
    }


    @GetMapping("/detail/{auditId}")
    public ResponseEntity<WebAppAuditEntryDto> getDetail(@PathVariable("auditId") long auditId) {
        WebAppAuditEntryDto dto = auditEntryService.findByIdStrippedDown(auditId);
        if( null == dto)
            return ResponseEntity.notFound().build();
        return ResponseEntity.ok(dto);
    }

}
