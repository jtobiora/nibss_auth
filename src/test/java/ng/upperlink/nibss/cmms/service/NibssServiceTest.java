package ng.upperlink.nibss.cmms.service;

import ng.upperlink.nibss.cmms.CmmsAuthApplication;
import ng.upperlink.nibss.cmms.config.email.MailConfigImpl;
import ng.upperlink.nibss.cmms.dto.search.PageSearchWithDate;
import ng.upperlink.nibss.cmms.dto.transactionReport.TabularReport;
import ng.upperlink.nibss.cmms.encryptanddecrypt.NIBSSAESEncryption;
import ng.upperlink.nibss.cmms.util.email.EmailService;
import ng.upperlink.nibss.cmms.util.email.SmtpMailSender;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.data.domain.Page;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.test.context.junit4.SpringRunner;
import org.thymeleaf.spring4.SpringTemplateEngine;

/**
 * Created by stanlee on 14/07/2018.
 */
@RunWith(SpringRunner.class)
@DataJpaTest
@SpringBootTest(classes = CmmsAuthApplication.class) //this is used because we have more than one main class @SpringBootApplication, one from this project while the other from the lib project but we choose this project's main class.
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class NibssServiceTest {

    @TestConfiguration
    static class NibssServiceTestContextConfiguration{

        @Autowired
        private Environment environment;

        @Bean
        public NibssService nibssService(){
            return new NibssService();
        }
/*
        @Bean
        public AgentTransactionReportService agentTransactionReportService(){
            return new AgentTransactionReportService();
        }*/

        @Bean
        public UserService userService(){
            return new UserService();
        }

        @Bean
        public RoleService roleService(){
            return new RoleService();
        }

        @Bean
        public MailConfigImpl mailConfig(){
            return new MailConfigImpl();
        }

        @Bean
        public EmailService emailService(){
            return new EmailService();
        }

        @Bean
        public SpringTemplateEngine springTemplateEngine(){
            return new SpringTemplateEngine();
        }

        @Bean
        public JavaMailSenderImpl javaMailSender(){
            return new JavaMailSenderImpl();
        }

        @Bean
        public SmtpMailSender smtpMailSender(){
            return new SmtpMailSender(environment,mailConfig(),emailService());
        }

        @Bean
        public LgaService lgaService(){
            return new LgaService();
        }

        @Bean
        public StateService stateService(){
            return new StateService();
        }

        @Bean
        public CountryService countryService(){
            return new CountryService();
        }

        @Bean
        public NIBSSAESEncryption nibssaesEncryption(){
            return new NIBSSAESEncryption();
        }

        @Bean
        public SubscriberService agentMgrService(){
            return new SubscriberService();
        }

    }

    @Autowired
    private NibssService nibssService;



/*    @MockBean //this is used to bypass the actual repo object
    private NibssRepo nibssRepo;

    @Before
    public void runBefore(){

        Nibss nibss = new Nibss();
        Mockito.when(nibssRepo.getOne(Long.valueOf("1"))).thenReturn(nibss);
        System.out.println("The nibss response "+ nibss);

    }*/

    @Test
    public void testMethod(){

//        //get all Nibss user from the system
//        Nibss nibss = nibssService.get(Long.valueOf("1"));
//
//        System.out.println("The Nibss object gotten is "+nibss);

       /* Page<TabularReport> tabularReportGroupByInstitution = agentTransactionReportService.getTabularReportGroupByInstitution(new PageSearchWithDate());

        tabularReportGroupByInstitution.forEach(tabularReport -> {
            System.out.println("The dashboard is "+tabularReport);
        });*/

        //Assert.assertNotEquals(tabularReportGroupByInstitution.getTotalElements(), Long.valueOf("0").longValue());

    }

}
