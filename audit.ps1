Get-ADFineGrainedPasswordPolicy -Filter * | 
Select Name, AppliesTo, MinPasswordLength, MinPasswordAge, MaxPasswordAge, PasswordHistoryCount, 
ComplexityEnabled, ReversibleEncryptionEnabled, LockoutThreshold, LockoutDuration, LockoutObservationWindow |
Format-Table
