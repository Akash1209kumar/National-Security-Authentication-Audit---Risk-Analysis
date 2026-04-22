
IF OBJECT_ID('Silver_Logs', 'U') IS NOT NULL DROP TABLE Silver_Logs;
GO

-- . TRANSFORMATION PIPELINE
WITH Cleaned_Pipeline AS (
    SELECT 
        TRIM(Request_ID) AS Request_ID,

        -- STATIC TIMESTAMP 
        CAST(
            COALESCE(
                TRY_CAST(TRIM(Timestamp) AS DATETIME), 
                '2026-04-10 00:00:00'
            ) AS DATETIME
        ) AS Clean_Timestamp,

        -- GLOBAL DISTRICT FORMATTING
        CASE 
            WHEN UPPER(TRIM(District)) LIKE 'S%EX%' THEN 'South-Ex'
            ELSE UPPER(LEFT(TRIM(District), 1)) + LOWER(SUBSTRING(TRIM(District), 2, LEN(TRIM(District))))
        END AS Standardized_District,

        -- GLOBAL MODALITY CLEANUP
        CASE 
            WHEN TRIM(Modality) = 'B@io' THEN 'Fingerprint'
            ELSE TRIM(Modality)
        END AS Standardized_Modality,

        TRIM(Operator_ID) AS Operator_ID,

        -- TYPE CASTING & AUDIT 
        -- Removed TRIM here because Latency_MS is already a float
        COALESCE(CAST(Latency_MS AS INT), -1) AS Latency_INT,

       
        UPPER(TRIM(Status)) AS Status,
        Internal_Code

    FROM Raw_logs
)
-- 3. FINAL 
SELECT * INTO cleaned_Logs FROM Cleaned_Pipeline;
GO
select * from cleaned_Logs


--1)The FRAUD Check (Targeting 0ms)
--Instead of looking for fraud, lookING for the "Fastest" operators. In a biometric system, speed is suspicious.

SELECT 
    Operator_ID, 
    MIN(Latency_INT) AS Fastest_Transaction,
    AVG(Latency_INT) AS Average_Speed,
    COUNT(*) AS Total_Logs
FROM cleaned_Logs
WHERE Status = 'SUCCESS'
GROUP BY Operator_ID
ORDER BY Fastest_Transaction ASC;




/*2)"I performed a Cross-District Variance Analysis to isolate regional friction. 
My logic was simple: if the software were the root cause, 
the failure rate would be statistically consistent across the nation. However, 
I identified a 4% delta in Dwarka and 5% in south ex compared to the system baseline of 14%. By isolating this 'Sore Thumb,' 
I moved the investigation away from a global software patch and toward a localized Hardware Audit,
specifically targeting sensor calibration in the high-failure nodes."*/
WITH cte AS (
    SELECT 
        Standardized_District, 
        Standardized_Modality,
        COUNT(*) AS Total_Attempts,
        ROUND(
            (CAST(SUM(CASE WHEN Status = 'FAILURE' THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*)) * 100, 
            2
        ) AS Failure_Rate_Percent
    FROM cleaned_Logs
    GROUP BY Standardized_District, Standardized_Modality -- Must group by both
)
SELECT * FROM cte 
WHERE Standardized_District IN ('South-Ex', 'Dwarka') -- Focus on the "Sore Thumbs"
ORDER BY Failure_Rate_Percent DESC;



//*3    Separating "User Error" from "System Failure"

Inside that 31% failure rate in South-Ex, there are two types of failures:

The "User" Failure: A person moved their finger, or they have dry skin. The system tries to scan, fails in 200ms, and moves on. This is Normal Noise.

The "System" Failure: The software hits a bug and gets stuck. It spins and spins until the server "kills" the connection at exactly 999ms. This is an Infinite Loop.

Why it’s necessary: You don't want to blame the hardware if the software is actually "hanging." If you see a massive cluster of 999ms in South-Ex, it means the scanners aren't just "old" **/

SELECT 
    Standardized_District,
    Standardized_Modality,
    COUNT(*) AS Total_Failures,
    -- Count how many hit the "999ms" Infinite Loop Wall
    SUM(CASE WHEN Latency_INT >= 999 THEN 1 ELSE 0 END) AS Infinite_Loop_Count,
    -- Count how many failed quickly (Normal Noise)
    SUM(CASE WHEN Latency_INT < 999 THEN 1 ELSE 0 END) AS Normal_Noise_Failures,
    -- Calculate the "Loop Ratio"
    ROUND(CAST(SUM(CASE WHEN Latency_INT >= 999 THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*) * 100, 2) AS Loop_Intensity_Percent
FROM cleaned_Logs
WHERE Status = 'FAILURE' 
  AND Standardized_District IN ('South-Ex', 'Dwarka')
GROUP BY Standardized_District, Standardized_Modality
ORDER BY Loop_Intensity_Percent DESC;

/*  output : Scenario A: High Normal Noise (The Hardware Problem)
If Normal_Noise_Failures is high but Infinite_Loop_Count is low:

WHAT I DISCOVERED: The software is fine, but the sensor is struggling to read the finger/eye.

The Fix: Clean the scanners or replace the hardware.

Scenario B: High Loop Intensity (The Software Problem)
If Loop_Intensity_Percent is high (e.g., > 20% of your failures are hitting 999ms):

The Diagnosis: This is an Infinite Loop. The Fingerprint Driver or Iris API is "hanging."

The Fix: Don't buy new hardware! Update the Driver Software or the API Version.*/



  
  --flagging every finding 


  -- 1. Create the Forensic Gold Layer
IF OBJECT_ID('Gold_Forensic_Logs', 'U') IS NOT NULL DROP TABLE Gold_Forensic_Logs;
GO

WITH Stats AS (
    SELECT 
        AVG(Latency_INT) as mu, 
        STDEV(Latency_INT) as sigma 
    FROM cleaned_Logs 
    WHERE Latency_INT > 0 AND Latency_INT < 999
)
SELECT 
    L.*,
    CASE 
        -- 1. The Physics Defier (Bypass Fraud)
        WHEN L.Latency_INT = 0 AND L.Status = 'SUCCESS' THEN 'SECURITY_BYPASS_FRAUD'
        
        -- 2. The Clock-Sync Issues (Negative values)
        WHEN L.Latency_INT < 0 AND L.Latency_INT != -1 THEN 'CLOCK_SYNC_ERROR'
        
        -- 3. The Infinite Loops (The 54% spike we just found)
        WHEN L.Latency_INT >= 999 THEN 'INFINITE_LOOP_OUTLIER'
        
        -- 4. Statistical Outliers (Anything beyond 3-Sigma)
        WHEN L.Latency_INT > (SELECT (mu + 3*sigma) FROM Stats) THEN 'STATISTICAL_LATENCY_OUTLIER'
        
        -- 5. The Corrupt Logs
        WHEN L.Latency_INT = -1 THEN 'SYSTEM_LOG_CORRUPTION'
        
        -- 6. Healthy Operations
        ELSE 'NORMAL_OPERATION'
    END AS Forensic_Tag
INTO Gold_Forensic_Logs
FROM cleaned_Logs AS L;
GO



/*  I applied the Three-Sigma Rule to establish a non-arbitrary threshold for system performance. 
By calculating the system baseline ($\mu$) and volatility ($\sigma$), 
I defined a boundary that captures 99.7% of healthy traffic.
Any data points exceeding this $\mu + 3\sigma$ limit were categorized as Statistical Outliers. 
This allowed me to objectively isolate 'Infinite Loops' and 'Hardware Friction' without relying on subjective guesswork  */
-- 1. Drop the table if it exists to ensure a clean run


----creating the flag table of all our findings




-- 2. Calculate the 3-Sigma logic and Flag the anomalies
WITH Stats AS (
    SELECT 
        AVG(Latency_INT) as mu, 
        STDEV(Latency_INT) as sigma 
    FROM cleaned_Logs 
    WHERE Latency_INT > 0 AND Latency_INT < 999
)
SELECT 
    L.*,
    CASE 
        -- 1. Physics Defier (0ms Success = Fraud)
        WHEN L.Latency_INT = 0 AND L.Status = 'SUCCESS' THEN 'SECURITY_BYPASS_FRAUD'
        
        -- 2. Clock-Sync Issues (-99ms)
        WHEN L.Latency_INT < 0 AND L.Latency_INT != -1 THEN 'CLOCK_SYNC_ERROR'
        
        -- 3. The Infinite Loops (The 999ms Wall)
        WHEN L.Latency_INT >= 999 THEN 'INFINITE_LOOP_OUTLIER'
        
        -- 4. Statistical Outliers (Beyond 3-Sigma Fence)
        WHEN L.Latency_INT > (SELECT (mu + 3*sigma) FROM Stats) THEN 'STATISTICAL_LATENCY_OUTLIER'
        
        -- 5. Corrupt Logs
        WHEN L.Latency_INT = -1 THEN 'SYSTEM_LOG_CORRUPTION'
        
        -- 6. Healthy Operations
        ELSE 'NORMAL_OPERATION'
    END AS Forensic_Tag
INTO main_finding_flagged -- Table name standardized
FROM cleaned_Logs AS L;
GO

-- 3. The Final Audit Verification
SELECT 
    Forensic_Tag, 
    COUNT(*) AS Total_Count,
    MIN(Latency_INT) AS Min_Latency,
    MAX(Latency_INT) AS Max_Latency,
    AVG(Latency_INT) AS Avg_Latency
FROM main_finding_flagged
GROUP BY Forensic_Tag
ORDER BY Total_Count DESC;

