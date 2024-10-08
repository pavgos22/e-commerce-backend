package com.projects.auth.service;

import com.projects.auth.entity.ResetOperations;
import com.projects.auth.entity.User;
import com.projects.auth.repository.ResetOperationsRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@EnableScheduling
public class ResetOperationService {

    private final ResetOperationsRepository resetOperationsRepository;


    @Transactional
    public ResetOperations initResetOperation(User user){
        ResetOperations resetOperations = new ResetOperations();

        resetOperations.setUid(UUID.randomUUID().toString());
        resetOperations.setCreateDate(new Timestamp(System.currentTimeMillis()).toString());
        resetOperations.setUser(user);

        resetOperationsRepository.deleteAllByUser(user);

        return resetOperationsRepository.saveAndFlush(resetOperations);
    }

    public void endOperation(String uid){
        resetOperationsRepository.findByUid(uid).ifPresent(resetOperationsRepository::delete);
    }

    @Scheduled(cron = "0 0/15 * * * *")
    protected void deleteExpireOperation(){
        List<ResetOperations> resetOperations = resetOperationsRepository.findExpiredOperations();
        if (resetOperations != null && !resetOperations.isEmpty()){
            resetOperationsRepository.deleteAll(resetOperations);
        }
    }

}